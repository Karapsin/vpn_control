"""Run exact Windows PowerShell 5.1 harness programs as owned private scripts.

`powershell.exe -Command -` executes redirected standard input like typed
interactive input (about_PowerShell_exe): statements run one at a time, so a
statement-terminating error does not stop the following lines, and a
multi-line statement waits for a blank line. An unterminated block is silently
discarded at end of input with exit code 0 (PowerShell/PowerShell#21644).
Harness programs therefore run complete through -File, and every reply
failure reports the complete streams instead of a shortened diff.
"""
import json
import subprocess
import tempfile
from pathlib import Path

ARGUMENTS = ('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File')


def run_program(powershell, program, timeout):
    """Run the exact program bytes once from a private temporary .ps1 file."""
    # Windows PowerShell 5.1 decodes a BOM-less script with the ANSI code page.
    if type(program) is not bytes or not program or not program.isascii():
        raise ValueError('windows-powershell-program-ascii')
    with tempfile.TemporaryDirectory(prefix='vpn-control-ps51-') as directory:
        path = Path(directory) / 'program.ps1'
        with open(path, 'xb') as stream:
            stream.write(program)
        try:
            return subprocess.run([str(powershell), *ARGUMENTS, str(path)], stdin=subprocess.DEVNULL,
                                  capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            partial = subprocess.CompletedProcess(error.cmd, None, error.stdout or b'', error.stderr or b'')
            raise AssertionError('Windows PowerShell timed out after %ss\n%s' % (timeout, reply_detail(partial))) from error


def reply_detail(reply):
    """Complete public reply text for assertion messages."""
    streams = ''.join('\n--- %s (%d bytes) ---\n%s' % (name, len(data), data.decode('utf-8', 'backslashreplace'))
                      for name, data in (('stdout', reply.stdout), ('stderr', reply.stderr)))
    return 'Windows PowerShell returncode=%r%s\n--- end ---' % (reply.returncode, streams)


def json_reply(case, reply):
    """Require exit 0, empty stderr and one JSON stdout value; return it with the reply detail."""
    detail = reply_detail(reply)
    case.assertEqual(reply.returncode, 0, detail)
    case.assertEqual(reply.stderr, b'', detail)
    try:
        value = json.loads(reply.stdout)
    except ValueError as error:
        case.fail('Windows PowerShell stdout is not one JSON value (%s)\n%s' % (error, detail))
    return value, detail
