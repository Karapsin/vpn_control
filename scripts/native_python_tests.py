"""Build a direct interpreter request for disposable native test guests.

The caller verifies the interpreter/tool provenance and owns the guest. This
module creates no process, installs nothing and changes no persistent environment.
"""
import json
import re


# Paths are data in argv, never interpolated into Python or shell source. Keep the
# child bootstrap self-contained so a guest needs only the selected test inputs.
_BOOTSTRAP = """import json, os, sys, unittest
test_directory, tool_json, *modules = sys.argv[1:]
tools = json.loads(tool_json)
sys.path.insert(0, test_directory)
if tools:
    os.environ['PATH'] = os.pathsep.join(tools + [os.environ.get('PATH', '')])
suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
result = unittest.TextTestRunner(verbosity=2).run(suite)
print(json.dumps({'selected': result.testsRun, 'executed': result.testsRun-len(result.skipped),
                  'skipped': [(test.id(), reason) for test, reason in result.skipped],
                  'failures': len(result.failures),
                  'errors': len(result.errors)}))
sys.exit(0 if result.testsRun and result.wasSuccessful() else 1)
"""


def _argument(value):
    if not isinstance(value, str) or not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Native test argument must be nonempty text without control characters")
    return value


def native_python_request(interpreter, test_directory, tool_directories, modules):
    interpreter, test_directory = _argument(interpreter), _argument(test_directory)
    tools = [_argument(path) for path in tool_directories]
    names = [_argument(name) for name in modules]
    if not names or any(not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", name, re.ASCII) for name in names):
        raise ValueError("Select explicit Python test modules or test names")
    return {"path": interpreter,
            "arg": ["-B", "-c", _BOOTSTRAP, test_directory, json.dumps(tools), *names],
            "capture-output": True}
