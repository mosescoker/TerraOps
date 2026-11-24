import os,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
with tempfile.TemporaryDirectory() as td:
 os.environ['TERRAOPS_WORKSPACE_ROOT']=str(Path(td)/'work')
 import server as s
 os.environ.pop('TERRAOPS_WORKSPACE_ROOT')
class Tools(unittest.TestCase):
 def test_inventory(self):
  rows=s.tool_inventory(); self.assertEqual(len(rows),len(set(s.TOOLS))); self.assertTrue(next(r for r in rows if r['name']=='python')['path']); self.assertTrue(all(r['version'] is None for r in rows))
 def test_probe(self):
  with patch.object(s,'tool_path',return_value='/example/git'),patch.object(s.subprocess,'run') as run:
   run.return_value.returncode=0;run.return_value.stdout='git version 2.45.1\nsecret example';r=s.inspect_tool('git','Core',True);self.assertEqual(r['version'],'2.45.1');self.assertNotIn('secret',str(r));self.assertEqual(run.call_args.kwargs['timeout'],4);self.assertFalse(run.call_args.kwargs['shell'])
 def test_missing(self):
  with patch.object(s,'tool_path',return_value=None),patch.object(s.subprocess,'run') as run:
   self.assertEqual(s.inspect_tool('git','Core',True)['status'],'missing');run.assert_not_called()
if __name__=='__main__':unittest.main()
