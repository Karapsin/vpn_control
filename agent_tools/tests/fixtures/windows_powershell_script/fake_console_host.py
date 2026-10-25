"""PUBLIC model of Windows PowerShell 5.1 console-host program intake; it never runs PowerShell.

Arguments follow powershell.exe. `-Command -` ports ConsoleHost InputLoop.Run for
redirected standard input without a prompt (PowerShell v6.0.0 ConsoleHost.cs, the
open-source successor of the Windows PowerShell 5.1 host): each line is parsed as if
typed at the prompt; an incomplete statement enters block mode, which only a
whitespace line ends; end of input discards a pending block and ends the session
(about_PowerShell_exe for 5.1, PowerShell/PowerShell#21644).
`-File <path>.ps1` runs the complete file as one script.

The modelled harness programs print their one result line from their final
statement, so a JSON summary stands in for that line only when the final statement
ran (exit code 0). VPN_CONTROL_FAKE_PS51_TRANSCRIPT names a new file that receives
the complete intake transcript. VPN_CONTROL_FAKE_PS51_REPLY names a recorded public
reply to replay instead of the summary. VPN_CONTROL_FAKE_PS51_EXECUTE=add-type
instead runs the executed statements through the Add-Type error-flow model below.
"""
import base64
import hashlib
import json
import os
import re
import sys

CLOSE = {')': '(', '}': '{', ']': '['}


class Unsupported(ValueError):
    pass


def incomplete(text):
    """Conservative parse completeness: open bracket, quote or comment, or a trailing pipe/comma."""
    stack, quote, last, i = [], None, '', 0
    while i < len(text):
        c, following = text[i], text[i + 1:i + 2]
        if quote:
            if quote == '"' and c == '`':
                i += 2
                continue
            if quote == '"' and c == '$' and following == '(':
                raise Unsupported('subexpression inside a double-quoted string')
            if c == quote:
                if following == quote:
                    i += 2
                    continue
                quote, last = None, c
            i += 1
            continue
        if c == '@' and following in ('"', "'"):
            raise Unsupported('here-string')
        if c == '<' and following == '#':
            end = text.find('#>', i + 2)
            if end < 0:
                return True
            i = end + 2
            continue
        if c == '#' and (i == 0 or text[i - 1] in ' \t\r\n;{}()|'):
            end = text.find('\n', i)
            i = len(text) if end < 0 else end
            continue
        if c == '`':
            if i + 1 >= len(text):
                return True
            i, last = i + 2, '`'
            continue
        if c in ('"', "'"):
            quote = c
        elif c in '({[':
            stack.append(c)
        elif c in CLOSE and (not stack or stack.pop() != CLOSE[c]):
            return False  # a parse error is complete input; the real host reports it
        if not c.isspace():
            last = c
        i += 1
    return bool(stack) or quote is not None or last in ('|', ',')


def stdin_units(text):
    """Executed units and the discarded pending block of one redirected stdin session."""
    lines = re.split(r'\r\n|\r|\n', text)
    if lines[-1] == '':
        lines.pop()  # ReadLine returns null after the final line terminator
    units, block = [], None
    for line in lines:
        if not line.strip():
            if block is None:
                continue
            line, block = block, None  # a whitespace line ends block mode and executes the block
        elif block is not None:
            block += '\n' + line  # block mode only accumulates
            continue
        if incomplete(line):
            block = line  # IncompleteParseException enters (or re-enters) block mode
        else:
            units.append(line)
    return units, block  # end of input: a pending block is never executed


# Add-Type error flow, from public PowerShell v6.0.0 sources. AddType.cs
# HandleCompilerErrors/OutputError write one non-terminating SOURCE_CODE_ERROR per
# compiler diagnostic, then ThrowTerminatingError(COMPILER_ERRORS). MshCommandRuntime
# SetupVariable gives -ErrorVariable a new list; ThrowTerminatingError/ManageException
# also append the CmdletInvocationException to it. Under $ErrorActionPreference='Stop'
# an uncaught error ends the running script, while try/catch receives it as $_.
# ConsoleHost reports an error that ends the -File script on stderr and exits 1; under
# -Command - InputLoop.Run reports the error of that one line (HandleErrors,
# ReportException) and reads on, and DoRunspaceLoop exits with $? of the last line.
# Only the STATEMENTS forms run: Windows console and assembly setup is inert, and any
# other statement, Add-Type source or preference is refused.
ADD_TYPE = 'Microsoft.PowerShell.Commands.AddTypeCommand'
# Modelled compiler verdicts by SHA-256 of the -TypeDefinition text: one diagnostic on
# each line where an authenticated windows_compile_followup source differs from the
# compiling native.fixed (test_windows_powershell_script checks these lines against the
# fixtures); the actual csc diagnostics are Windows-only.
COMPILER = {
    'd6873f948fa50eabeb9ddf5507b9c3765d522abe5b4cdd25abcc023334699740': (248, 286),  # native.before
    '69158117dc5ca71234cec0b60bb07932863536da957a5df6114ef1d093bd5ff1': (286,),  # native.exit-fixed
    '813ef9554080dd4b4e2b2d82c1e56b73992d09b233b98ad1d53698fd885bbea3': (),  # native.fixed
}
COMPILER_ERRORS = {'command': 'Add-Type', 'text': 'Cannot add type. Compilation errors occurred.',
                   'id': 'COMPILER_ERRORS,' + ADD_TYPE, 'category': 'InvalidData: (:) [Add-Type], InvalidOperationException'}


class Raised(Exception):
    """A terminating error record leaving its statement."""

    def __init__(self, record):
        super().__init__(record['id'])
        self.record = record


def split_top(text, separators):
    """(offset, part) pairs of one line split outside quotes and brackets; a # comment ends the line."""
    parts, depth, quote, start, i = [], 0, None, 0, 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == quote and text[i + 1:i + 2] == quote:
                i += 1  # a doubled quote stays inside the string
            elif c == quote:
                quote = None
            elif quote == '"' and c in '`$':
                raise Unsupported('expandable string')
        elif c == '#' and (i == 0 or text[i - 1] in ' \t;{}()|'):
            break
        elif c in '\'"':
            quote = c
        elif c in '({[':
            depth += 1
        elif c in CLOSE:
            depth -= 1
            if depth < 0:
                raise Unsupported('unbalanced %r' % c)
        elif depth == 0 and c in separators:
            parts.append((start, text[start:i]))
            start = i + 1
        i += 1
    if quote or depth:
        raise Unsupported('statement continues past its line')
    parts.append((start, text[start:i]))
    return [(offset + len(part) - len(part.lstrip()), part.strip()) for offset, part in parts if part.strip()]


def diagnostic(source, line):
    """OutputError text: '(line) : error', then lines line-1..line+1 with '>>> ' on the error line."""
    lines = source.split('\n')
    text = '(%d) : modelled compiler error\r\n' % line
    for number in range(max(line - 1, 1), min(line + 1, len(lines)) + 1):
        text += '\r\n(%d) : %s%s\r\n' % (number, '>>> ' if number == line else '', lines[number - 1])
    return text


def error_view(record, where, number, column, line, statement):
    """Windows PowerShell 5.1 console error view (CRLF) of an uncaught error, without width truncation."""
    return '\r\n'.join(('%s : %s' % (record['command'], record['text']), 'At %s:%d char:%d' % (where, number, column),
                        '+ ' + line.rstrip(), '+ ' + ' ' * (column - 1) + '~' * len(statement),
                        '    + CategoryInfo          : ' + record['category'],
                        '    + FullyQualifiedErrorId : ' + record['id'], ' ', ''))


def variable(state, name):
    if name.lower() not in state['variables']:
        raise Unsupported('unset variable $' + name)
    return state['variables'][name.lower()]


def evaluate(state, expression):
    """$true, $false, (@($a).Count -eq 0 -and ...) or @($a|ForEach-Object {projection})."""
    if expression in ('$true', '$false'):
        return expression == '$true'
    match = re.fullmatch(r'\((.*)\)', expression)
    counts = [re.fullmatch(r'@\(\$(\w+)\)\.Count -eq 0', part) for part in match.group(1).split(' -and ')] if match else [None]
    if all(counts):
        return all(not variable(state, count.group(1)) for count in counts)
    match = re.fullmatch(r'@\(\$(\w+)\|ForEach-Object \{(.*)\}\)', expression)
    if match:
        return [project(record, match.group(2)) for record in variable(state, match.group(1))]
    raise Unsupported('expression %r' % expression[:80])


def project(record, expression):
    """Concatenated $_.ToString(), $_.FullyQualifiedErrorId ($null adds nothing) and single-quoted literals."""
    text = ''
    for _, term in split_top(expression, '+'):
        if term == '$_.ToString()':
            text += record['text']
        elif term == '$_.FullyQualifiedErrorId':
            text += record['id'] or ''
        elif re.fullmatch(r"'[^']*'", term):
            text += term[1:-1]
        else:
            raise Unsupported('projection term %r' % term[:80])
    return text


def assign_text(state, name, value):
    state['variables'][name.lower()] = value
    if name.lower() == 'erroractionpreference':
        state['preference'] = value.lower()


def assign_source(state, name, data):
    state['variables'][name.lower()] = base64.b64decode(data, validate=True).decode('utf-8')


def assign_empty(state, name):
    state['variables'][name.lower()] = []


def assign_caught(state, name):
    if state['caught'] is None:
        raise Unsupported('$_ outside a catch block')
    state['variables'][name.lower()] = [state['caught']]


def try_catch(state, body, handler):
    try:
        run_statements(state, body)
    except Raised as error:
        outer, state['caught'] = state['caught'], error.record
        try:
            run_statements(state, handler)
        finally:
            state['caught'] = outer


def add_type(state, assemblies, name, error_variable):
    source = state['variables'].get(name.lower())
    lines = COMPILER.get(hashlib.sha256(source.encode()).hexdigest()) if isinstance(source, str) else None
    if lines is None:
        raise Unsupported('Add-Type source outside the authenticated windows_compile_followup chain')
    collected = state['variables'][error_variable.lower()] = []
    # -ErrorAction Continue writes each diagnostic to the error stream, which 2>$null discards.
    collected.extend({'text': diagnostic(source, line), 'id': 'SOURCE_CODE_ERROR,' + ADD_TYPE} for line in lines)
    if lines:
        collected.append({'text': 'System.Management.Automation.CmdletInvocationException: ' + COMPILER_ERRORS['text'], 'id': None})
        raise Raised(COMPILER_ERRORS)


def assign_ordered(state, name, entries):
    table = {}
    for _, entry in split_top(entries, ';'):
        key, equals, expression = entry.partition('=')
        if not equals or not re.fullmatch(r'\w+', key):
            raise Unsupported('hashtable entry %r' % entry[:80])
        table[key] = evaluate(state, expression)
    state['variables'][name.lower()] = table


def write_json(state, name):
    state['stdout'] += json.dumps(variable(state, name), separators=(',', ':')) + '\r\n'


def inert(state):
    """Windows console encoding and assembly loading have no modelled error flow."""


STATEMENTS = tuple((re.compile(pattern), action) for pattern, action in (
    (r"\$(\w+)='([^']*)'", assign_text),
    (r"\$(\w+)=\[Text\.Encoding\]::UTF8\.GetString\(\[Convert\]::FromBase64String\('([A-Za-z0-9+/=]*)'\)\)", assign_source),
    (r'\$(\w+)=@\(\)', assign_empty),
    (r'\$(\w+)=@\(\$_\)', assign_caught),
    (r'try\{(.*)\}catch\{(.*)\}', try_catch),
    (r'Add-Type -ReferencedAssemblies @\((.*)\) -TypeDefinition \$(\w+) -ErrorAction Continue -ErrorVariable (\w+) 2>\$null', add_type),
    (r'\$(\w+)=\[ordered\]@\{(.*)\}', assign_ordered),
    (r'\[Console\]::WriteLine\(\(\$(\w+)\|ConvertTo-Json -Compress\)\)', write_json),
    (r'\[Console\]::OutputEncoding=\[Text\.UTF8Encoding\]::new\(\$false\)', inert),
    (r"'[\w.]+'(?:,'[\w.]+')*\|ForEach-Object \{\[void\]\[Reflection\.Assembly\]::LoadWithPartialName\(\$_\)\}", inert),
))


def run_statement(state, statement):
    for pattern, action in STATEMENTS:
        match = pattern.fullmatch(statement)
        if match:
            return action(state, *match.groups())
    raise Unsupported('statement outside the Add-Type error-flow model: %r' % statement[:80])


def run_statements(state, text):
    for _, statement in split_top(text, ';'):
        run_statement(state, statement)


def run_script(state, script, where):
    """Run one script; under Stop an uncaught error ends it: (record, error view) or None."""
    for number, line in enumerate(script.split('\n'), 1):
        for offset, statement in split_top(line, ';'):
            try:
                run_statement(state, statement)
            except Raised as error:
                if state['preference'] != 'stop':
                    raise Unsupported('uncaught error under $ErrorActionPreference %r' % state['preference'])
                return error.record, error_view(error.record, where, number, offset + 1, line, statement)
    return None


def execute(intake, units, path):
    """Executed units through the error-flow model: stdout, stderr, exit code and uncaught [unit, id] pairs."""
    state = {'preference': 'continue', 'variables': {}, 'caught': None, 'stdout': ''}
    stderr, uncaught, failure = '', [], None
    for index, unit in enumerate(units, 1):
        if not unit.isascii():
            raise Unsupported('script text is modelled for ASCII only')
        failure = run_script(state, unit.decode('ascii'), path if intake == 'file' else 'line')
        if failure:
            stderr += failure[1]
            uncaught.append([index, failure[0]['id']])
    # The one -File script exits 1 when an error ended it; -Command - exits with $? of its last line.
    return state['stdout'].encode(), stderr.encode(), int(failure is not None), uncaught


def main(argv):
    flags, intake, path, i = {'-nologo', '-noprofile', '-noninteractive'}, None, None, 0
    while i < len(argv) and intake is None:
        word = argv[i].lower()
        if word in flags:
            i += 1
        elif word == '-executionpolicy' and i + 1 < len(argv):
            i += 2
        elif word == '-command' and argv[i + 1:] == ['-']:
            intake = 'stdin'
        elif word == '-file' and len(argv) == i + 2:
            intake, path = 'file', argv[i + 1]
        else:
            break
    if intake is None:
        sys.stderr.write('fake console host: unsupported powershell.exe arguments %r\n' % (argv,))
        return 64
    if intake == 'file':
        if not path.lower().endswith('.ps1'):
            sys.stderr.write("Processing -File '%s' failed because the file does not have a '.ps1' extension.\n" % path)
            return 64
        with open(path, 'rb') as stream:
            program = stream.read()
        units, discarded = [program], None
        try:
            stdin_null = os.path.samestat(os.fstat(0), os.stat(os.devnull))
        except OSError:
            stdin_null = False
    else:
        program, stdin_null = sys.stdin.buffer.read(), False
        try:
            if not program.isascii():
                raise Unsupported('console input decoding is modelled for ASCII only')
            units, discarded = stdin_units(program.decode('ascii'))
        except Unsupported as error:
            sys.stderr.write('fake console host: %s\n' % error)
            return 64
        units, discarded = [u.encode() for u in units], None if discarded is None else discarded.encode()
    flow, mode = None, os.environ.get('VPN_CONTROL_FAKE_PS51_EXECUTE')
    if mode:
        try:
            if mode != 'add-type':
                raise Unsupported('execution model %r' % mode)
            flow = execute(intake, units, path)
        except Unsupported as error:
            sys.stderr.write('fake console host: %s\n' % error)
            return 64
    encode = lambda data: None if data is None else base64.b64encode(data).decode()
    record = {'schemaVersion': 1, 'model': 'windows-powershell-5.1-console-host-intake', 'nativeExecution': False,
              'arguments': argv, 'intake': intake, 'scriptPath': path, 'stdinIsNull': stdin_null,
              'program': encode(program), 'units': [encode(u) for u in units], 'discarded': encode(discarded),
              'finalStatementRan': discarded is None and bool(units),
              'errorFlow': None if flow is None else {'exitCode': flow[2], 'uncaught': flow[3]}}
    if os.environ.get('VPN_CONTROL_FAKE_PS51_TRANSCRIPT'):
        with open(os.environ['VPN_CONTROL_FAKE_PS51_TRANSCRIPT'], 'x', encoding='ascii') as stream:
            json.dump(record, stream, sort_keys=True)
    if os.environ.get('VPN_CONTROL_FAKE_PS51_REPLY'):
        with open(os.environ['VPN_CONTROL_FAKE_PS51_REPLY'], encoding='ascii') as stream:
            reply = json.load(stream)
        sys.stdout.buffer.write(base64.b64decode(reply['stdout']))
        sys.stderr.buffer.write(base64.b64decode(reply['stderr']))
        return reply['returncode']
    if flow is not None:
        sys.stdout.buffer.write(flow[0])
        sys.stderr.buffer.write(flow[1])
        return flow[2]
    if record['finalStatementRan']:
        summary = {'model': record['model'], 'intake': intake, 'units': len(units),
                   'programSha256': hashlib.sha256(program).hexdigest()}
        sys.stdout.write(json.dumps(summary, sort_keys=True) + '\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
