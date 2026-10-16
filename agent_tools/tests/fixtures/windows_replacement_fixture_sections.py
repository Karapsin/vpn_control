"""Pure fixture extraction and parse-only diagnostics; never execute input bodies."""
import base64
import hashlib

OUTER_REPLACEMENT_CATCH = '}catch{$retired=$false;$provisioned=$false;$errorType='


def _replacement_fixture_bounds(task):
    if type(task) is not str or not 0 < len(task.encode('utf-8', errors='strict')) <= 65536:
        raise ValueError('replacement-fixture-task-bound')
    if task.count(OUTER_REPLACEMENT_CATCH) != 1 or task.count('\ntry{') != 1:
        raise ValueError('replacement-fixture-outer-boundary')
    start = task.index(OUTER_REPLACEMENT_CATCH)
    if start <= task.index('\ntry{'):
        raise ValueError('replacement-fixture-outer-order')
    return task.index('\ntry{'), start


def replacement_fixture_outer_catch(task):
    _, end = _replacement_fixture_bounds(task)
    return task[end:]


def replacement_fixture_finish(task, phase):
    if type(phase) is not str or phase not in ('retire', 'provision'):
        raise ValueError('replacement-fixture-phase')
    begin, end = _replacement_fixture_bounds(task)
    marker = ' if($retired)' if phase == 'retire' else ' if($provisioned)'
    begin += len('\ntry{')
    if task.count(marker, begin, end) != 1:
        raise ValueError('replacement-fixture-finish-boundary')
    start = task.index(marker, begin, end)
    return task[start:end]


_PARSER_OBSERVER = r"""$ErrorActionPreference='Stop';$cp117ObserveBytes=[Convert]::FromBase64String('@ENCODED@');if($cp117ObserveBytes.Length -ne @LENGTH@){throw 'PARSE_SOURCE_LENGTH'};$cp117ObserveSha=[BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($cp117ObserveBytes)).Replace('-','').ToLowerInvariant();if($cp117ObserveSha -cne '@SHA@'){throw 'PARSE_SOURCE_SHA'};$cp117ObserveBody=[Text.UTF8Encoding]::new($false,$true).GetString($cp117ObserveBytes);$cp117ObserveTokens=$null;$cp117ObserveErrors=$null;[void][Management.Automation.Language.Parser]::ParseInput($cp117ObserveBody,[ref]$cp117ObserveTokens,[ref]$cp117ObserveErrors);$cp117ObserveRows=@();foreach($cp117ObserveError in @($cp117ObserveErrors|Select-Object -First 64)){$cp117ObserveExtent=$cp117ObserveError.Extent;$cp117ObserveText=[string]$cp117ObserveExtent.Text;if($cp117ObserveText.Length -gt 4096){$cp117ObserveText=$cp117ObserveText.Substring(0,4096)};$cp117ObserveMessage=[string]$cp117ObserveError.Message;if($cp117ObserveMessage.Length -gt 4096){$cp117ObserveMessage=$cp117ObserveMessage.Substring(0,4096)};$cp117ObserveRows+=@{errorId=[string]$cp117ObserveError.ErrorId;message=$cp117ObserveMessage;incompleteInput=[bool]$cp117ObserveError.IncompleteInput;startLine=[int]$cp117ObserveExtent.StartLineNumber;startColumn=[int]$cp117ObserveExtent.StartColumnNumber;endLine=[int]$cp117ObserveExtent.EndLineNumber;endColumn=[int]$cp117ObserveExtent.EndColumnNumber;startOffset=[int]$cp117ObserveExtent.StartOffset;endOffset=[int]$cp117ObserveExtent.EndOffset;extentText=$cp117ObserveText}};[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);[Console]::Out.WriteLine((@{sourceSha256=$cp117ObserveSha;sourceBytes=$cp117ObserveBytes.Length;sourceExecuted=$false;parsed=($cp117ObserveErrors.Count -eq 0);errorCount=$cp117ObserveErrors.Count;errors=$cp117ObserveRows;truncated=($cp117ObserveErrors.Count -gt 64)}|ConvertTo-Json -Depth 6 -Compress))"""


def replacement_parse_only_observer(public):
    if type(public) is not bytes or not 0 < len(public) <= 262144:
        raise ValueError('replacement-parse-source-bound')
    public.decode('utf-8', errors='strict')
    script = _PARSER_OBSERVER.replace('@ENCODED@', base64.b64encode(public).decode('ascii'))
    script = script.replace('@LENGTH@', str(len(public)))
    script = script.replace('@SHA@', hashlib.sha256(public).hexdigest())
    encoded = script.encode('utf-8', errors='strict')
    if len(encoded) > 262144:
        raise ValueError('replacement-parse-wrapper-bound')
    return encoded
