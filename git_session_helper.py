"""Git credential helper: no persistence; exact HTTPS repository match."""
import os, sys
if len(sys.argv) != 2 or sys.argv[1] != 'get':
    sys.exit(0)
fields = {}
for line in sys.stdin:
    if not line.strip(): break
    key, sep, value = line.rstrip('\r\n').partition('=')
    if sep: fields[key] = value
expected = os.environ.get('TERRAOPS_GIT_REPO', '')
actual = fields.get('protocol','') + '://' + fields.get('host','') + '/' + fields.get('path','')
if expected and actual == expected:
    print('username=' + os.environ['TERRAOPS_GIT_USER'])
    print('password=' + os.environ['TERRAOPS_GIT_PAT'])
    print()
