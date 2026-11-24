import os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
with tempfile.TemporaryDirectory() as td:
 os.environ['TERRAOPS_WORKSPACE_ROOT']=str(Path(td)/'work')
 import server as s
 os.environ.pop('TERRAOPS_WORKSPACE_ROOT')
class Packages(unittest.TestCase):
 def test_preview(self):
  with patch.object(s,'package_manager',return_value=('winget','C:/winget.exe')):
   p=s.package_preview('terraform','install');self.assertEqual(p['command'],['winget','install','--id','Hashicorp.Terraform','--exact','--source','winget','--disable-interactivity'])
   for tool,op in [('git;bad','install'),('git','remove')]:
    with self.assertRaises(ValueError):s.package_preview(tool,op)
 def test_start(self):
  with patch.object(s,'package_manager',return_value=('brew','/usr/bin/brew')),patch.object(s,'PACKAGE_ENABLED',False),patch.object(s,'run_job') as run:
   with self.assertRaises(ValueError):s.package_start('git','install','INSTALL git')
   run.assert_not_called()
  with patch.object(s,'package_manager',return_value=('brew','/usr/bin/brew')),patch.object(s,'PACKAGE_ENABLED',True),patch.object(s,'tool_path',return_value=None),patch.object(s,'run_job',return_value='job') as run,patch.dict(os.environ,{'ARM_CLIENT_SECRET':'secret'}):
   with self.assertRaises(ValueError):s.package_start('git','install','wrong')
   self.assertEqual(s.package_start('git','install','INSTALL git'),'job');self.assertEqual(run.call_args.args[0],['/usr/bin/brew','install','git']);self.assertNotIn('ARM_CLIENT_SECRET',run.call_args.args[2]);self.assertTrue(run.call_args.kwargs['package'])
 def test_busy(self):
  with patch.object(s,'package_manager',return_value=('brew','/usr/bin/brew')),patch.object(s,'PACKAGE_ENABLED',True),patch.dict(s.ACTIVE,{'workspace':'job'}):
   with self.assertRaises(ValueError):s.package_start('git','install','INSTALL git')
if __name__=='__main__':unittest.main()
