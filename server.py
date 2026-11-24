import shlex, hashlib, tempfile, time, os, json, secrets, subprocess, threading, shutil, re, sys
from pathlib import Path
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
VERSION="0.3.8"
ROOT=Path(__file__).resolve().parent
TOKEN=secrets.token_urlsafe(32); JOBS={}; LOCK=threading.RLock(); PROFILES={}; PORT=8765
# Detection is separate from execution support. No installs or network probes.
TOOL_GROUPS={
 'Core / IaC':['python','git','terraform','tofu','terragrunt','packer'],
 'Configuration':['ansible','ansible-playbook','ansible-inventory','ansible-galaxy','ansible-lint','ssh','pwsh','powershell','wsl'],
 'Source control / CI':['gh','glab','git-credential-manager'],
 'Public cloud':['az','aws','gcloud','oci'],
 'Private cloud':['govc','pvesh','qm','openstack','oc','ncli'],
 'Containers':['docker','podman','kubectl','helm','argocd','kustomize'],
 'Security / validation':['checkov','trivy','gitleaks','tflint','opa','conftest','vault','infracost'],
 'Utilities':['jq','curl','code']}
TOOLS=[t for group in TOOL_GROUPS.values() for t in group]
EXECUTION_TOOLS={'git','terraform','ansible-playbook','ansible-inventory'}
# Only known local version commands; other tools are PATH-detection only.
VERSION_ARGS={t:['--version'] for t in ('git','terraform','tofu','terragrunt','packer','ansible','ansible-playbook','ansible-inventory','ansible-galaxy','ansible-lint','pwsh','gh','glab','git-credential-manager','az','aws','gcloud','oci','openstack','docker','podman','checkov','trivy','gitleaks','tflint','infracost','jq','curl')}
VERSION_ARGS.update({'python':['--version'],'kubectl':['version','--client','--output=json'],'helm':['version','--short'],'opa':['version'],'conftest':['--version'],'vault':['version']})
TOOL_SCAN_LOCK=threading.Lock()
def tool_path(name):
 return sys.executable if name=='python' else shutil.which(name)
def inspect_tool(name,group,versions=False):
 path=tool_path(name)
 row={'name':name,'category':group,'path':path,'status':'detected' if path else 'missing','version':None,'versionStatus':'not checked','execution':name in EXECUTION_TOOLS}
 if not path or not versions or name not in VERSION_ARGS:return row
 # Do not pass cloud session credentials or run in a project repository.
 env={k:v for k,v in os.environ.items() if k.upper() in {'PATH','PATHEXT','SYSTEMROOT','WINDIR','COMSPEC','HOME','USERPROFILE','TEMP','TMP','LOCALAPPDATA','APPDATA','LANG','LC_ALL'}}
 env.update({'AZURE_CORE_COLLECT_TELEMETRY':'false','CLOUDSDK_CORE_DISABLE_USAGE_REPORTING':'true','CHECKPOINT_DISABLE':'1','TF_IN_AUTOMATION':'1','GIT_TERMINAL_PROMPT':'0','NO_COLOR':'1'})
 try:
  result=subprocess.run([path,*VERSION_ARGS[name]],cwd=ROOT,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=4,encoding='utf-8',errors='replace',shell=False)
  match=re.search(r'(?<![\w.])v?(\d+\.\d+(?:\.\d+){0,2}(?:[-+][A-Za-z0-9.-]+)?)(?![\w.])',result.stdout[:8192])
  row['version']=match.group(1) if result.returncode==0 and match else None
  row['versionStatus']='available' if row['version'] else 'unavailable'
 except (OSError,subprocess.TimeoutExpired):row['versionStatus']='probe failed or timed out'
 return row

def tool_inventory(versions=False):
 from concurrent.futures import ThreadPoolExecutor
 entries=[(t,g) for g,ts in TOOL_GROUPS.items() for t in ts]
 if not versions:return [inspect_tool(t,g) for t,g in entries]
 if not TOOL_SCAN_LOCK.acquire(blocking=False):raise ValueError('Tool scan already running')
 try:
  with ThreadPoolExecutor(max_workers=8) as pool:return list(pool.map(lambda item:inspect_tool(*item,versions=True),entries))
 finally:TOOL_SCAN_LOCK.release()

# Explicit opt-in; package commands are server-owned, never supplied by the browser.
PACKAGE_ENABLED=os.environ.get('TERRAOPS_ENABLE_TOOL_INSTALL')=='1'
PACKAGES={
 'winget':{'git':'Git.Git','terraform':'Hashicorp.Terraform','kubectl':'Kubernetes.kubectl','helm':'Helm.Helm','pwsh':'Microsoft.PowerShell','code':'Microsoft.VisualStudioCode','gh':'GitHub.cli','az':'Microsoft.AzureCLI','aws':'Amazon.AWSCLI'},
 'brew':{'git':'git','terraform':'hashicorp/tap/terraform','tofu':'opentofu','terragrunt':'terragrunt','ansible':'ansible','ansible-lint':'ansible-lint','gh':'gh','glab':'glab','kubectl':'kubernetes-cli','helm':'helm','jq':'jq','trivy':'trivy','gitleaks':'gitleaks','tflint':'tflint','packer':'packer','aws':'awscli'}}
def package_manager():
 name='winget' if sys.platform=='win32' else 'brew'
 path=shutil.which(name)
 return name,path

def package_preview(tool,operation):
 manager,path=package_manager()
 if operation not in ('install','upgrade') or not isinstance(tool,str) or tool not in PACKAGES[manager]:raise ValueError('No approved package recipe for this tool or operation')
 package=PACKAGES[manager][tool]
 args=[manager,operation,'--id',package,'--exact','--source','winget','--disable-interactivity'] if manager=='winget' else [manager,operation,package]
 return {'tool':tool,'operation':operation,'manager':manager,'package':package,'command':args,'available':bool(path),'enabled':PACKAGE_ENABLED,'confirmation':operation.upper()+' '+tool}

def package_start(tool,operation,confirmation):
 preview=package_preview(tool,operation)
 if not PACKAGE_ENABLED:raise ValueError('Tool installation disabled; restart with TERRAOPS_ENABLE_TOOL_INSTALL=1')
 if not preview['available']:raise ValueError('Package manager not detected')
 if confirmation!=preview['confirmation']:raise ValueError('Typed confirmation required')
 with LOCK:
  if ACTIVE:raise ValueError('Wait for all jobs to finish before changing tools')
  if operation=='upgrade' and not tool_path(tool):raise ValueError('Tool not detected; use install or verify manually')
  if operation=='install' and tool_path(tool):raise ValueError('Tool already detected; use upgrade')
  # Any existing plan may rely on a binary that is about to change.
  for key in list(PLANS):invalidate(Path(key))
  manager,path=package_manager()
  env={k:v for k,v in os.environ.items() if k.upper() in {'PATH','PATHEXT','SYSTEMROOT','WINDIR','COMSPEC','HOME','USERPROFILE','TEMP','TMP','LOCALAPPDATA','APPDATA','PROGRAMFILES','PROGRAMFILES(X86)','PROGRAMDATA','LANG','LC_ALL','USER','LOGNAME','SHELL','HOMEDRIVE','HOMEPATH','XDG_CONFIG_HOME','XDG_CACHE_HOME'}}
  env.update({'HOMEBREW_NO_ANALYTICS':'1','HOMEBREW_NO_ENV_HINTS':'1','NONINTERACTIVE':'1'})
  command=[path,*preview['command'][1:]]
  return run_job(command,ROOT,env,package=True)

CONFIG=ROOT/'settings.json'
def linklike(p):
 return p.is_symlink() or getattr(p,'is_junction',lambda:False)()
def validate_root(value):
 if not isinstance(value,str) or not value.strip() or '\x00' in value: raise ValueError('Invalid workspace directory')
 raw=Path(os.path.expandvars(os.path.expanduser(value.strip())))
 if not raw.is_absolute() or str(raw).startswith(('\\\\','//')): raise ValueError('Use an absolute local directory')
 if any(linklike(x) for x in (raw,*raw.parents)): raise ValueError('Symlink or junction rejected')
 p=raw.resolve()
 if p==Path(p.anchor) or p==ROOT or p in ROOT.parents or (ROOT in p.parents and p!=ROOT/'workspace' and ROOT/'workspace' not in p.parents): raise ValueError('Choose a dedicated workspace directory')
 p.mkdir(parents=True,exist_ok=True)
 return p
SETTINGS=json.loads(CONFIG.read_text(encoding='utf-8')) if CONFIG.exists() else {}
WORK=validate_root(os.environ.get('TERRAOPS_WORKSPACE_ROOT') or SETTINGS.get('workspace_root',str(ROOT/'workspace')))
def repo(name):
 if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}',name): raise ValueError('Invalid workspace name')
 if re.fullmatch(r'CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]',name,re.I): raise ValueError('Reserved workspace name')
 if linklike(WORK) or WORK.resolve()!=WORK: raise ValueError('Workspace root changed on disk')
 candidate=WORK/name
 if linklike(candidate): raise ValueError('Symlink or junction rejected')
 p=candidate.resolve()
 if p.parent!=WORK: raise ValueError('Invalid workspace path')
 return p
def workspace_info(name):
 p=repo(name)
 return {'name':name,'path':str(p),'exists':p.is_dir(),'git':(p/'.git').exists(),'terraform':any(p.glob('*.tf')),'ansible':(p/'playbook.yml').is_file()}
def workspace_list():
 result=[]
 for p in sorted(WORK.iterdir()):
  if p.is_dir():
   try: result.append(workspace_info(p.name))
   except ValueError: pass
 return {'workspaceRoot':str(WORK),'workspaces':result}
GIT_HOSTS={'GitHub':'github.com','GitLab':'gitlab.com'}
def validate_git_url(provider,url):
 if provider not in GIT_HOSTS or not isinstance(url,str): raise ValueError('Invalid Git provider or URL')
 url=url.strip()
 host=re.escape(GIT_HOSTS[provider])
 if not re.fullmatch(r'https://'+host+r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\.git',url) or any(x in ('.','..') for x in url.split('/')[3:]): raise ValueError('Use a '+provider+' HTTPS repository .git URL without credentials')
 return url
def git_settings():
 return {k:SETTINGS.get('git_repositories',{}).get(k,'') for k in GIT_HOSTS}
def persist_settings(new):
 temp=CONFIG.with_suffix('.tmp')
 temp.write_text(json.dumps(new,indent=2),encoding='utf-8')
 os.replace(temp,CONFIG)
 SETTINGS.update(new)
def set_git_url(provider,url):
 if provider not in GIT_HOSTS or not isinstance(url,str): raise ValueError('Invalid Git provider or URL')
 urls=git_settings()
 urls[provider]=validate_git_url(provider,url) if url.strip() else ''
 persist_settings({**SETTINGS,'git_repositories':urls})
 return {'message':provider+' repository settings saved','gitRepositories':urls}
GIT_AUTH={}
GIT_MODES=('existing','manager','session')
def git_auth_status():
 return {k:{'mode':GIT_AUTH.get(k,{}).get('mode','existing'),'configured':k in GIT_AUTH} for k in GIT_HOSTS}
def set_git_auth(provider,mode,user='',pat=''):
 if provider not in GIT_HOSTS or mode not in GIT_MODES: raise ValueError('Invalid Git authentication mode')
 if mode=='session':
  if not isinstance(user,str) or not re.fullmatch(r'[A-Za-z0-9_.@+-]{1,128}',user) or not isinstance(pat,str) or not re.fullmatch(r'[!-~]{1,4096}',pat): raise ValueError('Enter a valid username and token without whitespace')
  GIT_AUTH[provider]={'mode':mode,'user':user,'pat':pat}
 else: GIT_AUTH[provider]={'mode':mode}
 return {'message':provider+' authentication set for this session','gitAuth':git_auth_status()}
def git_command(provider,args,url):
 url=validate_git_url(provider,url)
 auth=GIT_AUTH.get(provider,{'mode':'existing'})
 env={k:v for k,v in os.environ.items() if not k.startswith(('GIT_TRACE','GIT_CONFIG','TERRAOPS_GIT_')) and k not in ('GIT_CURL_VERBOSE','GIT_SSL_NO_VERIFY')}
 env['GIT_TERMINAL_PROMPT']='0'; env['GCM_INTERACTIVE']='Never'
 options=[]
 if auth['mode']!='existing':
  options=['-c','credential.helper=']
  if auth['mode']=='manager': options+=['-c','credential.helper=manager']
  else:
   helper='!'+shlex.quote(Path(sys.executable).as_posix())+' '+shlex.quote((ROOT/'git_session_helper.py').as_posix())
   options+=['-c','credential.helper='+helper,'-c','credential.useHttpPath=true','-c','core.askPass=','-c','http.followRedirects=false','-c','http.sslVerify=true']
   env.pop('GIT_ASKPASS',None);env.pop('SSH_ASKPASS',None)
   env.update(TERRAOPS_GIT_REPO=url,TERRAOPS_GIT_USER=auth['user'],TERRAOPS_GIT_PAT=auth['pat'])
 return ['git']+options+args,env
def set_root(value):
 global WORK
 if os.environ.get('TERRAOPS_WORKSPACE_ROOT'): raise ValueError('Workspace root is locked by environment variable')
 if ACTIVE: raise ValueError('Wait for active jobs to finish before changing root')
 new=validate_root(value)
 persist_settings({**SETTINGS,'workspace_root':str(new)})
 for key in list(PLANS): invalidate(Path(key))
 WORK=new
 return {'message':'Workspace root saved','workspaceRoot':str(WORK)}
# Plans are private, temporary artifacts; never place them inside a Git workspace.
PLAN_DIR=tempfile.TemporaryDirectory(prefix='terraops-plans-')
PLANS={}; ACTIVE={}; PROCESSES={}; CANCELLED=set()
LOCAL_MUTATIONS=os.environ.get('TERRAOPS_ENABLE_LOCAL_MUTATIONS')=='1'
def fingerprint(p):
 h=hashlib.sha256()
 for root,dirs,files in os.walk(p,followlinks=False):
  dirs[:]=sorted(d for d in dirs if d not in ('.git','.terraform'))
  for n in dirs+files:
   if linklike(Path(root)/n): raise ValueError('Symlink in workspace rejected')
  for n in sorted(files):
   f=Path(root)/n
   if not f.is_file(): raise ValueError('Non-regular workspace file')
   h.update(str(f.relative_to(p)).encode('utf-8')); h.update(b'\0')
   with f.open('rb') as stream:
    for chunk in iter(lambda:stream.read(65536),b''): h.update(chunk)
 return h.hexdigest()
def file_digest(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as stream:
  for chunk in iter(lambda:stream.read(65536),b''): h.update(chunk)
 return h.hexdigest()
def env_digest(env):
 return hashlib.sha256(json.dumps(env,sort_keys=True).encode()).hexdigest()
def invalidate(p):
 old=PLANS.pop(str(p),None)
 if old: Path(old['path']).unlink(missing_ok=True)
def run_job(cmd,cwd,env=None,plan=None,consume=None,package=False):
 if not shutil.which(cmd[0]): raise ValueError(cmd[0]+' is not installed')
 key=str(cwd); j=secrets.token_hex(8)
 with LOCK:
  if key in ACTIVE or any(JOBS.get(j,{}).get('package') for j in ACTIVE.values()): raise ValueError('Workspace or package manager busy')
  ACTIVE[key]=j; JOBS[j]={'status':'running','output':'Job started. Sensitive raw output is withheld.\n','code':None,'action':next((x for x in cmd[1:] if x in ('clone','fetch','ls-remote')),cmd[1]),'workspace':cwd.name,'workspacePath':str(cwd),'started':time.time(),'package':package}
 def worker():
  code=-1; proc=None; summaries=[]
  try:
   proc=subprocess.Popen(cmd,cwd=cwd,env=env if env is not None else os.environ.copy(),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',shell=False)
   with LOCK:
    PROCESSES[j]=proc
    if j in CANCELLED: proc.terminate()
   for line in proc.stdout:
    line=line.strip()
    if cmd[0]=='terraform' and (re.fullmatch(r'Plan: \d+ to add, \d+ to change, \d+ to destroy\.',line) or line=='No changes. Your infrastructure matches the configuration.'):
     summaries.append(line)
     with LOCK: JOBS[j]['output']+=line if line.startswith('Plan:') else 'No infrastructure changes.'; JOBS[j]['output']+='\n'
   code=proc.wait()
   with LOCK:
    if plan and code==0 and j not in CANCELLED and Path(plan['path']).is_file():
     if len(summaries)==1 and fingerprint(cwd)==plan['fingerprint']:
      plan['artifact_digest']=file_digest(plan['path']); plan['summary']=JOBS[j]['output']; PLANS[key]=plan; JOBS[j]['output']+='Saved plan ready for review.\n'
     else: JOBS[j]['output']+='Workspace changed or a unique plan summary was unavailable; plan discarded.\n'
  except Exception:
   with LOCK: JOBS[j]['output']+='Execution or plan verification failed.\n'
   code=-1
  finally:
   if proc and proc.poll() is None: proc.kill(); proc.wait()
   with LOCK:
    if plan and PLANS.get(key) is not plan: Path(plan['path']).unlink(missing_ok=True)
    if consume: Path(consume).unlink(missing_ok=True)
    JOBS[j].update(status='cancelled' if j in CANCELLED else 'finished',code=code,ended=time.time())
    JOBS[j]['output']+=f'Process exited with code {code}.\n'; ACTIVE.pop(key,None); PROCESSES.pop(j,None); CANCELLED.discard(j)
 threading.Thread(target=worker,daemon=True).start(); return j
TEMPLATES={
 'Azure':('azurerm','hashicorp/azurerm','resource "azurerm_resource_group" "main" {\n  name = var.name\n  location = var.region\n}\n','provider "azurerm" { features {} }'),
 'AWS':('aws','hashicorp/aws','resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n  tags = { Name = var.name }\n}\n','provider "aws" { region = var.region }'),
 'Google Cloud':('google','hashicorp/google','resource "google_compute_network" "main" {\n  name = var.name\n  auto_create_subnetworks = false\n}\n','provider "google" { region = var.region }'),
 'OCI':('oci','oracle/oci','resource "oci_core_vcn" "main" {\n  compartment_id = var.compartment_id\n  cidr_blocks = ["10.0.0.0/16"]\n  display_name = var.name\n}\nvariable "compartment_id" { type = string }\n','provider "oci" { region = var.region }')}
def template(provider):
 if provider=='Ansible': return '---\n- name: Verify Linux connectivity\n  hosts: all\n  gather_facts: false\n  tasks:\n    - name: Ping hosts\n      ansible.builtin.ping:\n'
 key,source,body,config=TEMPLATES[provider]
 return f'terraform {{\n  required_providers {{\n    {key} = {{ source = "{source}" }}\n  }}\n}}\n{config}\nvariable "name" {{ type = string }}\nvariable "region" {{ type = string }}\n'+body
# Catalog entries are standalone alternatives, not cumulative modules.
EXTRAS={
 'Azure': {'Storage account': 'resource "azurerm_resource_group" "main" {\n name = var.name\n location = var.region\n}\nresource "azurerm_storage_account" "main" {\n name = var.storage_name\n resource_group_name = azurerm_resource_group.main.name\n location = var.region\n account_tier = "Standard"\n account_replication_type = "LRS"\n allow_nested_items_to_be_public = false\n}\nvariable "storage_name" { type = string }\n', 'Virtual network': 'resource "azurerm_resource_group" "main" {\n name = var.name\n location = var.region\n}\nresource "azurerm_virtual_network" "main" {\n name = var.name\n location = var.region\n resource_group_name = azurerm_resource_group.main.name\n address_space = ["10.0.0.0/16"]\n}\n'},
 'AWS': {'S3 bucket': 'resource "aws_s3_bucket" "main" { bucket = var.name }\nresource "aws_s3_bucket_public_access_block" "main" {\n bucket = aws_s3_bucket.main.id\n block_public_acls = true\n block_public_policy = true\n ignore_public_acls = true\n restrict_public_buckets = true\n}\n','Security group': 'resource "aws_security_group" "main" {\n name = var.name\n vpc_id = var.vpc_id\n}\nvariable "vpc_id" { type = string }\n'},
 'Google Cloud': {'Storage bucket': 'resource "google_storage_bucket" "main" {\n name = var.name\n location = var.region\n uniform_bucket_level_access = true\n public_access_prevention = "enforced"\n}\n','Service account': 'resource "google_service_account" "main" { account_id = var.name }\n'},
 'OCI': {'Object storage bucket': 'resource "oci_objectstorage_bucket" "main" {\n compartment_id = var.compartment_id\n namespace = var.namespace\n name = var.name\n access_type = "NoPublicAccess"\n}\nvariable "compartment_id" { type = string }\nvariable "namespace" { type = string }\n','Network security group': 'resource "oci_core_network_security_group" "main" {\n compartment_id = var.compartment_id\n vcn_id = var.vcn_id\n display_name = var.name\n}\nvariable "compartment_id" { type = string }\nvariable "vcn_id" { type = string }\n'}}
PLAYBOOKS={
 'Connectivity': template('Ansible'),
 'Linux facts': '---\n- name: Collect Linux facts\n  hosts: all\n  gather_facts: true\n  tasks:\n    - ansible.builtin.debug:\n        msg: "{{ ansible_distribution }} {{ ansible_distribution_version }}"\n',
 'Disk usage': '---\n- name: Inspect disk usage\n  hosts: all\n  tasks:\n    - ansible.builtin.command: df -h\n      changed_when: false\n',
 'Install packages': '---\n- name: Install baseline packages\n  hosts: all\n  become: true\n  tasks:\n    - ansible.builtin.package:\n        name: [curl, git]\n        state: present\n',
 'Service health': '---\n- name: Collect service facts\n  hosts: all\n  tasks:\n    - ansible.builtin.service_facts:\n'}
PROFILE_KEYS={'Azure':['ARM_CLIENT_ID','ARM_TENANT_ID','ARM_SUBSCRIPTION_ID','ARM_CLIENT_SECRET'], 'AWS':['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_REGION'], 'Google Cloud':['GOOGLE_OAUTH_ACCESS_TOKEN','GOOGLE_PROJECT','GOOGLE_REGION'], 'OCI':['OCI_CLI_USER','OCI_CLI_TENANCY','OCI_CLI_FINGERPRINT','OCI_CLI_REGION']}
PRIVATE_PROFILE_KEYS={
 'VMware vSphere':['VSPHERE_SERVER','VSPHERE_USER','VSPHERE_PASSWORD'],
 'Proxmox':['PROXMOX_VE_ENDPOINT','PROXMOX_VE_API_TOKEN','PROXMOX_VE_USERNAME','PROXMOX_VE_PASSWORD'],
 'Hyper-V':['HYPERV_HOST','HYPERV_USERNAME','HYPERV_PASSWORD'],
 'OpenStack':['OS_AUTH_URL','OS_APPLICATION_CREDENTIAL_ID','OS_APPLICATION_CREDENTIAL_SECRET','OS_REGION_NAME'],
 'OpenShift':['KUBE_HOST','KUBE_TOKEN','KUBE_CLUSTER_CA_CERT_DATA'],
 'Nutanix HCI':['NUTANIX_ENDPOINT','NUTANIX_USERNAME','NUTANIX_PASSWORD'],
 'Kubernetes':['KUBE_HOST','KUBE_TOKEN','KUBE_CLUSTER_CA_CERT_DATA'],
 'Helm':['KUBE_HOST','KUBE_TOKEN','KUBE_CLUSTER_CA_CERT_DATA'],
 'Rancher':['RANCHER_URL','RANCHER_TOKEN_KEY'],
 'Custom Terraform variables':['TF_VAR_endpoint','TF_VAR_username','TF_VAR_password','TF_VAR_token']}
PROFILE_KEYS.update(PRIVATE_PROFILE_KEYS)
PROFILE_NOTES={
 'VMware vSphere':'vmware/vsphere; use a trusted vCenter certificate.',
 'Proxmox':'bpg/proxmox; use an API token or username/password, not both.',
 'Hyper-V':'taliesins/hyperv community provider; configure WinRM HTTPS and provider settings in HCL.',
 'OpenStack':'terraform-provider-openstack/openstack; Keystone application credentials.',
 'OpenShift':'hashicorp/kubernetes for Kubernetes-compatible resources; OpenShift-specific resources require compatible configuration.',
 'Nutanix HCI':'nutanix/nutanix; Prism endpoint and credentials.',
 'Kubernetes':'hashicorp/kubernetes; token and trusted CA certificate (PEM).',
 'Helm':'hashicorp/helm; configure its Kubernetes connection in HCL as required by your provider version.',
 'Rancher':'rancher/rancher2; API URL and token.',
 'Custom Terraform variables':'Declare matching sensitive Terraform variables in your trusted configuration. No arbitrary environment keys.'}

PRIVATE_TEMPLATES={'VMware vSphere': {'Datacenter lookup': 'terraform {\n  required_providers {\n    vsphere = {\n      source = "vmware/vsphere"\n    }\n  }\n}\nprovider "vsphere" {\n}\nvariable "datacenter" { type = string }\ndata "vsphere_datacenter" "selected" { name = var.datacenter }\n', 'Datacenter folder': 'terraform {\n  required_providers {\n    vsphere = {\n      source = "vmware/vsphere"\n    }\n  }\n}\nprovider "vsphere" {\n}\nvariable "datacenter" { type = string }\nvariable "name" { type = string }\ndata "vsphere_datacenter" "selected" { name = var.datacenter }\nresource "vsphere_folder" "main" {\n  path = var.name\n  type = "vm"\n  datacenter_id = data.vsphere_datacenter.selected.id\n}\n'}, 'Proxmox': {'Cluster nodes': 'terraform {\n  required_providers {\n    proxmox = {\n      source = "bpg/proxmox"\n    }\n  }\n}\nprovider "proxmox" {\n}\ndata "proxmox_virtual_environment_nodes" "main" {}\n', 'VM starter (no OS)': 'terraform {\n  required_providers {\n    proxmox = {\n      source = "bpg/proxmox"\n    }\n  }\n}\nprovider "proxmox" {\n}\nvariable "node_name" { type = string }\nvariable "name" { type = string }\nresource "proxmox_virtual_environment_vm" "main" {\n  name = var.name\n  node_name = var.node_name\n  started = false\n}\n'}, 'Hyper-V': {'Provider configuration': 'terraform {\n  required_providers {\n    hyperv = {\n      source = "taliesins/hyperv"\n    }\n  }\n}\nprovider "hyperv" {\n  host = var.host\n  user = var.username\n  password = var.password\n  https = true\n  port = 5986\n  insecure = false\n}\nvariable "host" { type = string }\nvariable "username" { type = string }\nvariable "password" {\n type = string\n sensitive = true\n}\n'}, 'OpenStack': {'Private network': 'terraform {\n  required_providers {\n    openstack = {\n      source = "terraform-provider-openstack/openstack"\n    }\n  }\n}\nprovider "openstack" {\n}\nvariable "name" { type = string }\nresource "openstack_networking_network_v2" "main" {\n name = var.name\n admin_state_up = true\n}\n'}, 'Nutanix HCI': {'Cluster discovery': 'terraform {\n  required_providers {\n    nutanix = {\n      source = "nutanix/nutanix"\n    }\n  }\n}\nprovider "nutanix" {\n}\ndata "nutanix_clusters" "main" {}\n'}, 'Rancher': {'Cluster lookup': 'terraform {\n  required_providers {\n    rancher2 = {\n      source = "rancher/rancher2"\n    }\n  }\n}\nprovider "rancher2" {\n}\nvariable "cluster_name" { type = string }\ndata "rancher2_cluster" "main" { name = var.cluster_name }\n'}, 'Helm': {'Local chart release': 'terraform {\n  required_providers {\n    helm = {\n      source = "hashicorp/helm"\n      version = "~> 3.0"\n    }\n  }\n}\nprovider "helm" {\n  kubernetes = {\n    host = var.host\n    token = var.token\n    cluster_ca_certificate = var.ca\n  }\n}\nvariable "host" { type = string }\nvariable "token" {\n type = string\n sensitive = true\n}\nvariable "ca" { type = string }\nvariable "chart_path" { type = string }\nresource "helm_release" "main" {\n name = "terraops-demo"\n chart = var.chart_path\n namespace = "default"\n}\n'}, 'Kubernetes': {'Namespace': 'terraform {\n  required_providers {\n    kubernetes = {\n      source = "hashicorp/kubernetes"\n    }\n  }\n}\nprovider "kubernetes" {\n}\nvariable "name" { type = string }\nresource "kubernetes_namespace_v1" "main" {\n metadata {\n  name = var.name\n }\n}\n', 'Namespace lookup': 'terraform {\n  required_providers {\n    kubernetes = {\n      source = "hashicorp/kubernetes"\n    }\n  }\n}\nprovider "kubernetes" {\n}\nvariable "name" { type = string }\ndata "kubernetes_namespace_v1" "main" {\n metadata {\n  name = var.name\n }\n}\n'}, 'OpenShift': {'Namespace': 'terraform {\n  required_providers {\n    kubernetes = {\n      source = "hashicorp/kubernetes"\n    }\n  }\n}\nprovider "kubernetes" {\n}\nvariable "name" { type = string }\nresource "kubernetes_namespace_v1" "main" {\n metadata {\n  name = var.name\n }\n}\n', 'Namespace lookup': 'terraform {\n  required_providers {\n    kubernetes = {\n      source = "hashicorp/kubernetes"\n    }\n  }\n}\nprovider "kubernetes" {\n}\nvariable "name" { type = string }\ndata "kubernetes_namespace_v1" "main" {\n metadata {\n  name = var.name\n }\n}\n'}, 'Custom Terraform variables': {'Variable contract': 'variable "endpoint" { type = string }\nvariable "username" { type = string }\nvariable "password" {\n type = string\n sensitive = true\n}\nvariable "token" {\n type = string\n sensitive = true\n}\n# Add a trusted provider and resources; this contract creates nothing.\n'}}
PLAYBOOKS.update({'VMware vSphere - server facts': '---\n- name: Read vCenter facts\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n    - name: Query platform\n      community.vmware.vmware_about_info:\n        hostname: "{{ lookup(\'ansible.builtin.env\', \'VSPHERE_SERVER\') }}"\n        username: "{{ lookup(\'ansible.builtin.env\', \'VSPHERE_USER\') }}"\n        password: "{{ lookup(\'ansible.builtin.env\', \'VSPHERE_PASSWORD\') }}"\n        validate_certs: true\n      no_log: true\n      changed_when: false\n', 'Proxmox - API discovery': '---\n- name: Read Proxmox API\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n    - name: Query platform\n      ansible.builtin.uri:\n        url: "{{ lookup(\'ansible.builtin.env\', \'PROXMOX_VE_ENDPOINT\') | regex_replace(\'/+$\', \'\') }}/api2/json/nodes"\n        method: GET\n        headers: {Authorization: "PVEAPIToken={{ lookup(\'ansible.builtin.env\', \'PROXMOX_VE_API_TOKEN\') }}"}\n        validate_certs: true\n        follow_redirects: none\n        return_content: false\n        status_code: 200\n      no_log: true\n      changed_when: false\n', 'Kubernetes - API discovery': '---\n- name: Read Kubernetes API\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n    - name: Query platform\n      ansible.builtin.uri:\n        url: "{{ lookup(\'ansible.builtin.env\', \'KUBE_HOST\') | regex_replace(\'/+$\', \'\') }}/version"\n        method: GET\n        headers: {Authorization: "Bearer {{ lookup(\'ansible.builtin.env\', \'KUBE_TOKEN\') }}"}\n        validate_certs: true\n        follow_redirects: none\n        return_content: false\n        status_code: 200\n      no_log: true\n      changed_when: false\n', 'OpenShift - API discovery': '---\n- name: Read OpenShift API\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n    - name: Query platform\n      ansible.builtin.uri:\n        url: "{{ lookup(\'ansible.builtin.env\', \'KUBE_HOST\') | regex_replace(\'/+$\', \'\') }}/version"\n        method: GET\n        headers: {Authorization: "Bearer {{ lookup(\'ansible.builtin.env\', \'KUBE_TOKEN\') }}"}\n        validate_certs: true\n        follow_redirects: none\n        return_content: false\n        status_code: 200\n      no_log: true\n      changed_when: false\n', 'Helm - API discovery': '---\n- name: Read Helm API\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n    - name: Query platform\n      ansible.builtin.uri:\n        url: "{{ lookup(\'ansible.builtin.env\', \'KUBE_HOST\') | regex_replace(\'/+$\', \'\') }}/version"\n        method: GET\n        headers: {Authorization: "Bearer {{ lookup(\'ansible.builtin.env\', \'KUBE_TOKEN\') }}"}\n        validate_certs: true\n        follow_redirects: none\n        return_content: false\n        status_code: 200\n      no_log: true\n      changed_when: false\n', 'Rancher - API discovery': '---\n- name: Read Rancher API\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n    - name: Query platform\n      ansible.builtin.uri:\n        url: "{{ lookup(\'ansible.builtin.env\', \'RANCHER_URL\') | regex_replace(\'/+$\', \'\') }}/v3/clusters"\n        method: GET\n        headers: {Authorization: "Bearer {{ lookup(\'ansible.builtin.env\', \'RANCHER_TOKEN_KEY\') }}"}\n        validate_certs: true\n        follow_redirects: none\n        return_content: false\n        status_code: 200\n      no_log: true\n      changed_when: false\n', 'OpenStack - server inventory': '---\n- name: Read OpenStack servers\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n    - name: Query platform\n      openstack.cloud.server_info: {}\n      no_log: true\n      changed_when: false\n', 'Nutanix HCI - cluster discovery': '---\n- name: Read Prism Central clusters\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n    - name: Query platform\n      ansible.builtin.uri:\n        url: "https://{{ lookup(\'ansible.builtin.env\', \'NUTANIX_ENDPOINT\') }}:9440/api/nutanix/v3/clusters/list"\n        method: POST\n        body_format: json\n        body: {kind: cluster}\n        url_username: "{{ lookup(\'ansible.builtin.env\', \'NUTANIX_USERNAME\') }}"\n        url_password: "{{ lookup(\'ansible.builtin.env\', \'NUTANIX_PASSWORD\') }}"\n        force_basic_auth: true\n        validate_certs: true\n        follow_redirects: none\n        status_code: 200\n      no_log: true\n      changed_when: false\n', 'Hyper-V - VM inventory': '---\n- name: Inspect Hyper-V hosts\n  hosts: hyperv\n  gather_facts: false\n  vars:\n    ansible_connection: winrm\n    ansible_winrm_scheme: https\n    ansible_port: 5986\n    ansible_winrm_server_cert_validation: validate\n    ansible_user: "{{ lookup(\'ansible.builtin.env\', \'HYPERV_USERNAME\') }}"\n    ansible_password: "{{ lookup(\'ansible.builtin.env\', \'HYPERV_PASSWORD\') }}"\n  tasks:\n    - name: Read VM inventory\n      ansible.windows.win_powershell:\n        script: Get-VM | Select-Object Name, State\n      changed_when: false\n      no_log: true\n', 'Private cloud - Linux baseline audit': '---\n- name: Inspect Linux guests\n  hosts: all\n  gather_facts: true\n  tasks:\n    - name: Collect service facts\n      ansible.builtin.service_facts:\n    - name: Check disk usage\n      ansible.builtin.command: df -h\n      changed_when: false\n'})
# API probes must never send credentials to plain HTTP or follow redirects.
for _name, _code in list(PLAYBOOKS.items()):
 if _name.endswith(' - API discovery'):
  _url_key={'Proxmox':'PROXMOX_VE_ENDPOINT','Rancher':'RANCHER_URL'}.get(_name.split(' - ')[0],'KUBE_HOST')
  _assert="    - name: Require HTTPS endpoint\n      ansible.builtin.assert:\n        that:\n          - lookup('ansible.builtin.env', '"+_url_key+"') is match('^https://[^/@]+(?:/.*)?$')\n      no_log: true\n"
  PLAYBOOKS[_name]=_code.replace('  tasks:\n','  tasks:\n'+_assert,1)
# Discovery plays are intentionally read-only and may execute in check mode.
for _name in list(PLAYBOOKS):
 if _name not in ('Connectivity','Linux facts','Disk usage','Install packages','Service health'):
  PLAYBOOKS[_name]=PLAYBOOKS[_name].replace('      changed_when: false','      check_mode: false\n      changed_when: false')
CATALOG={k:['Starter']+list(v) for k,v in EXTRAS.items()}; CATALOG['Ansible']=list(PLAYBOOKS); CATALOG.update({k:list(v) for k,v in PRIVATE_TEMPLATES.items()})
def catalog_code(provider,item):
 if provider=='Ansible': return PLAYBOOKS[item]
 if provider in PRIVATE_TEMPLATES: return PRIVATE_TEMPLATES[provider][item]
 if item=='Starter': return template(provider).replace('features {} }','features {}\n}') .replace('provider "azurerm" { features','provider "azurerm" {\n features')
 key,source,_,config=TEMPLATES[provider]
 if provider=='Azure': config='provider "azurerm" {\n features {}\n}'
 return 'terraform {\n required_providers {\n '+key+' = { source = "'+source+'" }\n }\n}\n'+config+'\nvariable "name" { type = string }\nvariable "region" { type = string }\n'+EXTRAS[provider][item]
def profile_env(name):
 env=os.environ.copy()
 if name:
  with LOCK:
   if name not in PROFILES: raise ValueError('Profile not found')
   env.update(PROFILES[name]['values'])
   provider=PROFILES[name]['provider']
   mapping={'Hyper-V':{'HYPERV_HOST':'TF_VAR_host','HYPERV_USERNAME':'TF_VAR_username','HYPERV_PASSWORD':'TF_VAR_password'},'Helm':{'KUBE_HOST':'TF_VAR_host','KUBE_TOKEN':'TF_VAR_token','KUBE_CLUSTER_CA_CERT_DATA':'TF_VAR_ca'}}.get(provider,{})
   for source,target in mapping.items():
    if source in PROFILES[name]['values']: env[target]=PROFILES[name]['values'][source]
 return env
IGNORE='\n.terraform/\n*.tfstate\n*.tfstate.*\n*.tfplan\n*.tfvars\n*.tfvars.json\n.env\n*.pem\n*.key\ncrash.log\n'
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def send(self,data,status=200,mime='application/json'):
  b=json.dumps(data).encode() if mime=='application/json' else data.encode(); self.send_response(status); self.send_header('Content-Type',mime+'; charset=utf-8'); self.send_header('Content-Length',str(len(b))); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'"); self.end_headers()
  try: self.wfile.write(b)
  except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError): pass
 def valid(self): return self.headers.get('Host')==f'127.0.0.1:{PORT}'
 def do_GET(self):
  if not self.valid(): return self.send({'error':'Invalid host'},403)
  path=self.path
  if path=='/api/session': return self.send({'version':VERSION,'token':TOKEN,'tools':{t:bool(tool_path(t)) for t in TOOLS},'catalog':CATALOG,'profileKeys':PROFILE_KEYS,'privateProviders':list(PRIVATE_PROFILE_KEYS),'profileNotes':PROFILE_NOTES,'localMutations':LOCAL_MUTATIONS,'workspaceRoot':str(WORK),'workspaceRootLocked':bool(os.environ.get('TERRAOPS_WORKSPACE_ROOT')),'gitRepositories':git_settings(),'gitAuth':git_auth_status()})
  if path in ('/api/tools','/api/tools?versions=1'):
   if self.headers.get('X-Token')!=TOKEN: return self.send({'error':'Forbidden'},403)
   try:return self.send({'tools':tool_inventory(path.endswith('=1')),'platform':sys.platform,'packageManager':package_manager()[0],'packageManagerAvailable':bool(package_manager()[1]),'packageEnabled':PACKAGE_ENABLED,'packages':PACKAGES[package_manager()[0]]})
   except ValueError as e:return self.send({'error':str(e)},409)
  if path=='/api/workspaces':
   if self.headers.get('X-Token')!=TOKEN: return self.send({'error':'Forbidden'},403)
   with LOCK: return self.send(workspace_list())
  if path.startswith('/api/job/'):
   if self.headers.get('X-Token')!=TOKEN: return self.send({'error':'Forbidden'},403)
   return self.send(JOBS.get(path.split('/')[-1],{'status':'unknown'}))
  files={'/':('index.html','text/html'),'/app.js':('app.js','text/javascript'),'/style.css':('style.css','text/css')}
  if path in files:
   f,m=files[path]; return self.send((ROOT/'static'/f).read_text(encoding='utf-8'),mime=m)
  self.send({'error':'Not found'},404)
 def do_POST(self):
  if not self.valid() or self.headers.get('Origin')!=f'http://127.0.0.1:{PORT}' or self.headers.get('X-Token')!=TOKEN: return self.send({'error':'Forbidden'},403)
  try:
   n=int(self.headers.get('Content-Length','0'))
   if not 0<n<1000000: raise ValueError('Invalid request size')
   d=json.loads(self.rfile.read(n).decode('utf-8')); a=d['action']
   with LOCK: return self.process_action(a,d)
  except PermissionError: self.send({'error':'Access denied to local directory'},403)
  except Exception as e: self.send({'error':str(e) if isinstance(e,ValueError) else 'Invalid request'},400)
 def process_action(self,a,d):
   if a=='package_preview':return self.send(package_preview(d['tool'],d['operation']))
   if a=='package_start':return self.send({'job':package_start(d['tool'],d['operation'],d.get('confirmation'))})
   if any(JOBS.get(j,{}).get('package') for j in ACTIVE.values()) and a not in ('history','workspace_list','workspace_info','workspace_root','profiles','git_settings','template'):raise ValueError('Package manager running; wait for completion')
   if a=='git_auth_save': return self.send(set_git_auth(d['provider'],d['mode'],d.get('username',''),d.get('pat','')))
   if a=='git_auth_clear':
    if d['provider'] not in GIT_HOSTS: raise ValueError('Invalid Git provider')
    GIT_AUTH.pop(d['provider'],None); return self.send({'message':'Session authentication cleared','gitAuth':git_auth_status()})
   if a=='git_test':
    provider=d['provider']; url=git_settings().get(provider,''); cmd,env=git_command(provider,['ls-remote','--',url],url)
    return self.send({'job':run_job(cmd,ROOT,env)})
   if a=='git_settings': return self.send({'gitRepositories':git_settings()})
   if a=='git_settings_save': return self.send(set_git_url(d['provider'],d['url']))
   if a=='workspace_root': return self.send({'workspaceRoot':str(WORK)})
   if a=='workspace_root_set': return self.send(set_root(d['path']))
   if a=='workspace_list': return self.send(workspace_list())
   if a=='workspace_info': return self.send(workspace_info(d['repo']))
   if a not in ('template','profiles','profile_save','profile_delete','history','cancel'):
    if d.get('workspaceRoot',str(WORK))!=str(WORK): raise ValueError('Workspace root changed; reload the page')
    p=repo(d.get('repo','demo'))
    if str(WORK) in ACTIVE or (str(p) in ACTIVE and a!='plan_info'): raise ValueError('Workspace busy')
   if a=='template': return self.send({'code':catalog_code(d['provider'],d.get('item',CATALOG[d['provider']][0]))})
   if a=='profiles':
    with LOCK: return self.send({'profiles':[{"name":k,"provider":v['provider']} for k,v in PROFILES.items()]})
   if a=='profile_save':
    name=d['name']; provider=d['provider']; values=d['values']
    if not isinstance(name,str) or provider not in PROFILE_KEYS or not re.fullmatch(r'[A-Za-z0-9_-]{1,40}',name) or not isinstance(values,dict) or any(k not in PROFILE_KEYS[provider] or not isinstance(v,str) or len(v)>16000 or '\x00' in v for k,v in values.items()): raise ValueError('Invalid profile')
    with LOCK: PROFILES[name]={'provider':provider,'values':{k:v for k,v in values.items() if v}}
    return self.send({'message':'Profile stored in process memory only'})
   if a=='profile_delete':
    with LOCK: PROFILES.pop(d['name'],None)
    return self.send({'message':'Profile removed'})
   if a=='history':
    with LOCK: return self.send({'jobs':[dict(v,id=k) for k,v in JOBS.items()]})
   if a=='cancel':
    with LOCK:
     j=d['job']; job=JOBS.get(j)
     if not job or job['status']!='running' or job.get('package') or job['action'] in ('apply','-i'): raise ValueError('Only running non-apply jobs can be cancelled')
     CANCELLED.add(j)
     if j in PROCESSES: PROCESSES[j].terminate()
    return self.send({'message':'Cancellation requested; child processes may require manual cleanup.'})
   if a=='clone':
    provider=d.get('gitProvider')
    if provider not in GIT_HOSTS: raise ValueError('Select GitHub or GitLab')
    url=validate_git_url(provider,git_settings()[provider])
    if p.exists(): raise ValueError('Workspace already exists')
    cmd,env=git_command(provider,['clone','--',url,str(p)],url)
    return self.send({'job':run_job(cmd,WORK,env),'path':str(p)})
   if a=='create':
    p.mkdir(exist_ok=True); f=p/'.gitignore'
    if linklike(f) or f.resolve().parent!=p: raise ValueError('Unsafe file path')
    if not f.exists(): f.write_text(IGNORE,encoding='utf-8')
    return self.send({'message':'Workspace ready','path':str(p),'name':p.name})
   if not p.is_dir(): raise ValueError('Create or clone a workspace first')
   if a in ('save','load'):
    name=d.get('file','playbook.yml' if d.get('provider')=='Ansible' else 'main.tf')
    if name not in ('main.tf','variables.tf','outputs.tf','providers.tf','backend.tf','playbook.yml','inventory.yml'): raise ValueError('Unsupported file')
    f=p/name
    if linklike(f) or f.resolve().parent!=p: raise ValueError('Unsafe file path')
    if a=='load': return self.send({'code':f.read_text(encoding='utf-8') if f.exists() else '','path':str(f)})
    with LOCK:
     if str(p) in ACTIVE: raise ValueError('Workspace busy')
     invalidate(p); f.write_text(d['code'],encoding='utf-8')
    return self.send({'message':'Saved '+f.name,'path':str(f)})
   if a=='fetch':
    if not shutil.which('git'): raise ValueError('git is not installed')
    result=subprocess.run(['git','config','--get','remote.origin.url'],cwd=p,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=5)
    url=result.stdout.strip(); provider=next((k for k,v in git_settings().items() if v and v==url),None)
    if not provider: raise ValueError('Origin must match a configured GitHub or GitLab URL in Environments')
    cmd,env=git_command(provider,['fetch','origin'],url); invalidate(p)
    return self.send({'job':run_job(cmd,p,env)})
   if a=='branch':
    b=d['branch'];
    if not re.fullmatch(r'feature/[A-Za-z0-9_-]+',b): raise ValueError('Use feature/name')
    invalidate(p)
    return self.send({'job':run_job(['git','switch','-c',b],p)})
   if a in ('plan','destroy_plan','apply','plan_info'):
    with LOCK:
     key=str(p)
     if a=='plan_info':
      x=PLANS.get(key); return self.send({'plan':{'id':x['id'],'destroy':x['destroy'],'summary':x['summary'],'localPath':x['path']} if x else None,'localMutations':LOCAL_MUTATIONS})
     if key in ACTIVE: raise ValueError('Workspace busy')
     env=profile_env(d.get('profile')); env={k:v for k,v in env.items() if not k.startswith('TF_CLI_ARGS')}; env['TF_IN_AUTOMATION']='1'
     digest=env_digest(env)
     if a=='apply':
      if not LOCAL_MUTATIONS or not p.name.startswith('dev-'): raise ValueError('Local apply requires explicit server opt-in and dev- workspace; production is pipeline-only')
      x=PLANS.get(key)
      if not x or x['id']!=d.get('plan_id') or x['fingerprint']!=fingerprint(p) or x['env']!=digest or not Path(x['path']).is_file() or file_digest(x['path'])!=x['artifact_digest'] or time.time()-x['created']>1800: raise ValueError('Plan missing, expired or stale; re-plan')
      expected=('DESTROY ' if x['destroy'] or re.search(r'[1-9]\d* to destroy',x['summary']) else 'APPLY ')+p.name
      if d.get('confirmation')!=expected: raise ValueError('Typed confirmation does not match')
      if not shutil.which('terraform'): raise ValueError('terraform is not installed')
      PLANS.pop(key)
      return self.send({'job':run_job(['terraform','apply','-input=false','-no-color',x['path']],p,env,consume=x['path'])})
     invalidate(p); ident=secrets.token_hex(12); dest=str(Path(PLAN_DIR.name)/(ident+'.tfplan'))
     x={'id':ident,'path':dest,'destroy':a=='destroy_plan','fingerprint':fingerprint(p),'env':digest,'created':time.time()}
     cmd=['terraform','plan','-input=false','-no-color','-out='+dest]+(['-destroy'] if x['destroy'] else [])
     return self.send({'job':run_job(cmd,p,env,plan=x)})
   if a in ('inventory','check','ansible_run'):
    if a=='ansible_run' and (not LOCAL_MUTATIONS or not p.name.startswith('dev-') or d.get('confirmation')!='RUN '+p.name): raise ValueError('Ansible run requires opt-in, dev- workspace and typed confirmation')
    cmd=['ansible-inventory','-i','inventory.yml','--list'] if a=='inventory' else ['ansible-playbook','-i','inventory.yml','playbook.yml']+(['--check'] if a=='check' else [])
    return self.send({'job':run_job(cmd,p,profile_env(d.get('profile')))})
   cmds={'fetch':['git','fetch'],'status':['git','status','--short'],'init':['terraform','init','-input=false','-no-color'],'fmt':['terraform','fmt','-check'],'validate':['terraform','validate','-no-color'],'plan':['terraform','plan','-input=false','-no-color'],'syntax':['ansible-playbook','--syntax-check','playbook.yml']}
   if a not in cmds: raise ValueError('Unsupported action; apply/destroy and publishing are pipeline-only in this MVP')
   with LOCK:
    if str(p) in ACTIVE: raise ValueError('Workspace busy')
    if a in ('init','fmt','fetch'): invalidate(p)
    return self.send({'job':run_job(cmds[a],p,profile_env(d.get('profile')) if a in ('init','validate') else None)})
if __name__=='__main__':
 print(f'TerraOps v{VERSION}: http://127.0.0.1:{PORT} | Workspace: {WORK}',flush=True); ThreadingHTTPServer(('127.0.0.1',PORT),Handler).serve_forever()
