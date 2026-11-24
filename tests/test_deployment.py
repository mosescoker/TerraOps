"""Offline deployment regression tests: simulate Terraform, never call a cloud."""
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

with tempfile.TemporaryDirectory() as root:
    os.environ['TERRAOPS_WORKSPACE_ROOT'] = root
    import server as s
    os.environ.pop('TERRAOPS_WORKSPACE_ROOT')

    class FakeProcess:
        def __init__(self, args, **kwargs):
            self.code = None
            destination = next((a[5:] for a in args if a.startswith('-out=')), None)
            if destination:
                Path(destination).write_bytes(b'simulated private plan')
            self.stdout = iter(self.lines)
        def wait(self):
            self.code = 0
            return 0
        def poll(self):
            return self.code
        def kill(self):
            self.code = -9
        def terminate(self):
            self.code = -15

    class DeploymentTests(unittest.TestCase):
        def setUp(self):
            self.workspace = s.repo('dev-test')
            self.workspace.mkdir(exist_ok=True)
            (self.workspace / 'main.tf').write_text('# test', encoding='utf-8')
            s.invalidate(self.workspace)
            self.destination = Path(s.PLAN_DIR.name) / 'test.tfplan'
            self.destination.unlink(missing_ok=True)

        def launch(self, lines):
            FakeProcess.lines = lines
            plan = {'id':'test', 'path':str(self.destination), 'destroy':False,
                    'fingerprint':s.fingerprint(self.workspace), 'env':'test', 'created':time.time()}
            with patch.object(s.shutil, 'which', return_value='fake-terraform'), patch.object(s.subprocess, 'Popen', FakeProcess):
                job = s.run_job(['terraform','plan','-out='+str(self.destination)], self.workspace, plan=plan)
                deadline = time.monotonic() + 5
                while s.JOBS[job]['status'] == 'running' and time.monotonic() < deadline:
                    time.sleep(.01)
            self.assertEqual(s.JOBS[job]['status'], 'finished')
            return s.JOBS[job]

        def test_valid_plan_and_digest(self):
            self.launch(['Plan: 1 to add, 0 to change, 0 to destroy.\n'])
            plan = s.PLANS[str(self.workspace)]
            self.assertEqual(plan['artifact_digest'], s.file_digest(self.destination))
            self.destination.write_bytes(b'modified plan')
            self.assertNotEqual(plan['artifact_digest'], s.file_digest(self.destination))

        def test_no_summary_discarded(self):
            job = self.launch(['sensitive arbitrary text\n'])
            self.assertNotIn(str(self.workspace), s.PLANS)
            self.assertFalse(self.destination.exists())
            self.assertNotIn('sensitive arbitrary text', job['output'])

        def test_ambiguous_summary_discarded(self):
            self.launch(['Plan: 1 to add, 0 to change, 0 to destroy.\n', 'Plan: 0 to add, 0 to change, 1 to destroy.\n'])
            self.assertNotIn(str(self.workspace), s.PLANS)
            self.assertFalse(self.destination.exists())

        def test_fingerprint_changes(self):
            before = s.fingerprint(self.workspace)
            (self.workspace / 'main.tf').write_text('# changed', encoding='utf-8')
            self.assertNotEqual(before, s.fingerprint(self.workspace))

    unittest.main()
