# Run from application directory: PYTHONPATH=. python tests/test_workspace.py
import os,tempfile,sys,json,threading,urllib.request,urllib.error
from pathlib import Path
with tempfile.TemporaryDirectory() as td:
 os.environ['TERRAOPS_WORKSPACE_ROOT']=str(Path(td)/'initial')
 import server as s
 os.environ.pop('TERRAOPS_WORKSPACE_ROOT');s.CONFIG=Path(td)/'settings.json';s.PORT=0
 http=s.ThreadingHTTPServer(('127.0.0.1',0),s.Handler);s.PORT=http.server_port
 threading.Thread(target=http.serve_forever,daemon=True).start();base=f'http://127.0.0.1:{s.PORT}'
 def call(a=None,**kw):
  req=urllib.request.Request(base+('/api/action' if a else '/api/session'),data=json.dumps(dict(action=a,**kw)).encode() if a else None,headers={'X-Token':s.TOKEN,'Origin':base,'Content-Type':'application/json'})
  try:
   with urllib.request.urlopen(req) as r:return json.load(r)
  except urllib.error.HTTPError as e:return json.load(e)
 root=str(Path(td)/'new folder ü');assert call('workspace_root_set',path=root)['workspaceRoot']==root
 assert json.loads(s.CONFIG.read_text())['workspace_root']==root
 assert call('create',repo='dev-azure')['path']==str(Path(root)/'dev-azure')
 assert call('save',repo='dev-azure',code='# café')['path'].endswith('main.tf')
 assert call('load',repo='dev-azure')['code']=='# café'
 assert call('workspace_list')['workspaces'][0]['name']=='dev-azure'
 assert call('plan_info',repo='dev-azure')['plan'] is None
 assert 'error' in call('apply',repo='dev-azure')
 assert 'error' in call('create',repo='../escape')
 assert 'error' in call('create',repo='CON')
 assert 'error' in call('create',repo='wrong',workspaceRoot='old')
 s.ACTIVE['test']='job';assert 'error' in call('workspace_root_set',path=str(Path(td)/'other'));s.ACTIVE.clear()
 (Path(root)/'link').symlink_to(Path(td),target_is_directory=True);assert 'error' in call('create',repo='link')
 assert call('template',provider='Azure')['code'];assert call('history')['jobs']==[]
 assert call('git_settings_save',provider='GitHub',url='https://github.com/org/repo.git')['gitRepositories']['GitHub'].endswith('/repo.git')
 assert call('git_settings_save',provider='GitLab',url='https://gitlab.com/group/sub/repo.git')['gitRepositories']['GitLab'].endswith('/repo.git')
 assert 'error' in call('git_settings_save',provider='GitHub',url='https://gitlab.com/group/repo.git')
 assert 'error' in call('git_settings_save',provider='GitHub',url='https://token@github.com/org/repo.git')
 assert call('workspace_root_set',path=str(Path(td)/'another'))['workspaceRoot']
 assert json.loads(s.CONFIG.read_text())['git_repositories']['GitHub']=='https://github.com/org/repo.git'
 original=s.run_job; commands=[]
 s.run_job=lambda cmd,cwd,*args,**kw: commands.append(cmd) or 'mock-job'
 assert call('clone',repo='dev-gh',gitProvider='GitHub')['job']=='mock-job'
 assert call('clone',repo='dev-gl',gitProvider='GitLab')['job']=='mock-job'
 assert commands[0][-2]=='https://github.com/org/repo.git' and commands[1][-2]=='https://gitlab.com/group/sub/repo.git'
 s.run_job=original
 assert call('git_settings_save',provider='GitLab',url='')['gitRepositories']['GitLab']==''
 session=call();assert len(session['privateProviders'])==10
 for provider in session['privateProviders']:
  key=session['profileKeys'][provider][0]
  assert call('profile_save',name='private',provider=provider,values={key:'test-marker'})['message']
  assert s.profile_env('private')[key]=='test-marker'
  assert 'test-marker' not in json.dumps(call('profiles'))
  assert 'test-marker' not in s.CONFIG.read_text()
  assert 'error' in call('profile_save',name='private',provider=provider,values={'PATH':'invalid'})
  assert call('profile_delete',name='private')['message']
  assert 'private' not in s.PROFILES
 assert 'error' in call('profile_save',name='private',provider='Unknown',values={})
 for provider,items in s.PRIVATE_TEMPLATES.items():
  for item,code in items.items():
   assert call('template',provider=provider,item=item)['code']==code
 for item,code in s.PLAYBOOKS.items():
  assert call('template',provider='Ansible',item=item)['code']==code
 assert call('create',repo='dev-private')['path']
 assert call('profile_save',name='test-helm',provider='Helm',values={'KUBE_TOKEN':'test-secret'})['message']
 assert s.profile_env('test-helm')['TF_VAR_token']=='test-secret'
 received=[]
 s.run_job=lambda cmd,cwd,env=None,**kw: received.append((cmd,env)) or 'mock-job'
 assert call('check',repo='dev-private',profile='test-helm')['job']=='mock-job'
 assert received[0][1]['KUBE_TOKEN']=='test-secret'
 s.run_job=original
 http.shutdown();http.server_close();print('API checks passed')
