import os, subprocess, sys, unittest
import server as s
class GitAuthTests(unittest.TestCase):
 def test_session(self):
  url='https://github.com/org/repo.git'
  s.set_git_auth('GitHub','session','tester','dummy-token')
  cmd,env=s.git_command('GitHub',['ls-remote','--',url],url)
  self.assertNotIn('dummy-token',str(cmd)); self.assertNotIn('dummy-token',str(s.git_auth_status()))
  # Exercise real Git's credential protocol, without contacting any server.
  base=cmd[:-3]
  def fill(path):
   return subprocess.run(base+['credential','fill'],input='protocol=https\nhost=github.com\npath='+path+'\n\n',env=env,text=True,capture_output=True)
  r=fill('org/repo.git'); self.assertEqual(r.returncode,0,r.stderr); self.assertIn('password=dummy-token',r.stdout)
  r=fill('org/other.git'); self.assertNotIn('dummy-token',r.stdout)
  s.GIT_AUTH.clear()
 def test_modes(self):
  url='https://gitlab.com/group/repo.git'
  s.set_git_auth('GitLab','manager'); cmd,env=s.git_command('GitLab',['ls-remote','--',url],url)
  self.assertIn('credential.helper=manager',cmd);self.assertNotIn('TERRAOPS_GIT_PAT',env)
  with self.assertRaises(ValueError): s.set_git_auth('GitLab','session','test','bad\nvalue')
  s.GIT_AUTH.clear()
if __name__=='__main__': unittest.main()
