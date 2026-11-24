# TerraOps Console — v0.3.6

## Existing workspace picker
Choose a workspace from the searchable selector on any page. Refresh after creating folders outside TerraOps. Only direct child directories of the configured workspace root with supported names are listed. Switching clears the editor buffer after confirmation and is blocked while the tracked job runs. No workspace is automatically selected at startup.


A clean consolidated release of the original v0.1 portable application architecture with the v0.3.4 feature set. Python standard library, static HTML/CSS/JavaScript, no CDN, no database and no required third-party Python packages for the console.

## Start
- Windows: extract the archive, enter `terraops`, run `start.bat` or `python server.py`.
- Linux/macOS: enter `terraops` and run `sh start.sh`.
- Open http://127.0.0.1:8765. Stop any previous server first.
- Install Git, Terraform and relevant cloud CLIs separately. Run the whole console inside WSL/Linux if using Ansible on Windows.

## Guided workflow
1. Dashboard: inspect actual catalog counts and detected tools.
2. Repository: choose a dedicated absolute workspace root, save, and create or select a project. The root persists in settings.json. Use `TERRAOPS_WORKSPACE_ROOT` before startup to override and lock the root. Changing it does not move old projects and invalidates saved plans.
3. Environments: configure separate GitHub/GitLab HTTPS `.git` URLs for public github.com and gitlab.com; clone using existing Git credentials. Save public/private cloud profiles in session memory. Profile removal does not revoke credentials or stop running processes. No PAT manager or live connection test yet.
4. Terraform Library / Ansible Library: generate a standalone starter, review, then save in Editor. Templates are alternatives, not cumulative modules. Supply required variables through trusted configuration or inherited TF_VAR variables. Do not put secrets in code. Provider version and schema validation are required before use.
5. Terraform: initialize, format-check, validate, plan or destroy-plan. Safe summary polling only. Review the full plan privately using `terraform show` with the saved plan path shown by the console when local apply is enabled. Local mutation is disabled by default.
6. Ansible: generate an inventory, syntax-check, inspect inventory, run check mode, or use guarded local execution. Check mode is not a security boundary.
7. History: session-only job history. GitHub/GitLab pipeline page describes the external workflow; publishing and pipeline generation/execution are not implemented.

## Catalog
26 Terraform starters: Azure, AWS, Google Cloud, OCI, VMware vSphere, Proxmox VE, Hyper-V, OpenStack, OpenShift, Nutanix HCI, Kubernetes, Helm, Rancher and custom variables. 15 Ansible playbooks and two inventory examples. 14 profile types (4 public, 10 private/container/custom). Hyper-V and custom Terraform starters are configuration contracts, not provisioning modules. Most private-cloud playbooks are discovery/audit examples. Proxmox uses bpg/proxmox. Helm starter expects provider 3.x and a local chart. OCI requires provider-compatible credentials. Kubernetes-family API discovery requires system CA trust. Install Ansible collections/SDKs separately as needed: community.vmware, openstack.cloud, ansible.windows, pyvmomi, openstacksdk, pywinrm.

## Experimental deployment safety
- Loopback host/origin/token checks, fixed CLI arguments, path validation, one active job per workspace, session profiles, suppressed raw CLI output.
- Saved plans are temporary files outside the workspace. Require one recognized plan summary, matching configuration/environment fingerprint, matching plan-file digest, 30-minute expiry and typed confirmation. This is not an independent security boundary or full plan review.
- Local mutations are OFF unless `TERRAOPS_ENABLE_LOCAL_MUTATIONS=1` is set before startup. Only `dev-` workspaces are accepted. Use disposable isolated cloud accounts with restricted credentials. Names do not prove isolation. Production belongs in reviewed external pipelines; the app cannot enforce cloud-side policy.
- Terraform/Ansible/Git may execute code from repositories, plugins or providers. Never run untrusted repositories. No sandbox. External processes and edits are not locked. Child processes may survive cancellation; apply and playbook executions cannot be cancelled through the console.
- Plans, state, OS paging, provider caches and external Git credential helpers may store sensitive information. Git ignore rules for new workspaces are not a complete secret prevention mechanism. Raw logs are withheld rather than fully redacted.

## Offline scope
UI, editor, generator and local catalog operate offline. Clone/fetch, provider downloads, remote backends, cloud APIs and CI/CD require connectivity unless using suitable local mirrors/caches.

## Tests
From the application directory:
```
python -m py_compile server.py
node --check static/app.js
```
Linux/macOS: `PYTHONPATH=. python tests/test_workspace.py` and `PYTHONPATH=. python tests/test_deployment.py`.
Windows PowerShell: `$env:PYTHONPATH='.'` then `python tests/test_workspace.py` and `python tests/test_deployment.py` (symlink test may require Developer Mode or privileges).

This build passed Python and JS syntax checks, local HTTP API regression checks and four simulated deployment tests on Linux. Actual provider validation, real remote Git operations, Ansible runs, Windows runtime, browser end-to-end testing and security audit are not completed. No Terraform or Ansible binaries were available during testing. This is a development release, not production-ready.

## v0.3.5 — Git authentication
Environments has separate GitHub and GitLab authentication choices: existing Git configuration, Git Credential Manager (`manager`, installed and authenticated separately), or a session-only username/PAT. Save the HTTPS repository URL, save authentication, then test repository access (`git ls-remote`). An exit code of zero confirms read access, not write permission. Clone and fetch use the selected provider mode; fetch requires origin to match the configured URL. PATs are passed in child process environment variables to a non-persisting Git helper scoped to the exact HTTPS repository. They are not included in settings or command arguments. Git Credential Manager and existing helpers may persist credentials independently. Session clear does not revoke tokens or interrupt running jobs. Only use trusted repositories and local Git configuration; subprocess environment is not a security sandbox. No live remote or Windows tests were performed.

## v0.3.7 — Tools on this machine
Open Tools, Dashboard, Repository or Settings to view the categorized tool inventory. Refresh detection rescans the server PATH; Check installed versions explicitly runs allowlisted version commands with a four-second timeout per tool. Versions are best-effort and only version strings are returned. Other tools are detection-only. No automatic installs or cloud connectivity checks are performed. A detected executable is not evidence of working credentials, provider compatibility or an implemented execution integration. Run TerraOps in WSL to discover WSL-local Ansible tools. Restart TerraOps after changing the system PATH. Only run trusted local executables; third-party CLI version commands may have their own side effects or telemetry.
