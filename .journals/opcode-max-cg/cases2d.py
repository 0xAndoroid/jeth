import sys; sys.path.insert(0, '/tmp/opcg')
import cases2
CASES = [c for c in cases2.CASES if c['name'] in ('MODEXP/1024-32-1024', 'MODEXP/1024-32-1024even')]
