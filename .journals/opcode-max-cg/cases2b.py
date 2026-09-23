import sys; sys.path.insert(0, '/tmp/opcg')
import cases2
FAILED = {'CALL/value-existing', 'CALL/cold-new-value', 'SSTORE/cold-new', 'CREATE/empty', 'CREATE/init48K', 'CREATE2/empty', 'CREATE2/init48K'}
CASES = [c for c in cases2.CASES if c['name'] in FAILED]
