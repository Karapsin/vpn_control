"""Rename only the authenticated public task command definition and its 14 calls.
The caller must first authenticate the whole emitted task through its retained
original emitter/source bindings. This function supplies no native admission.
"""
import hashlib,re
OLD='Cli'
NEW='Invoke-Cp117PublicCli'
FUNCTION_BEFORE_SHA='53e36ce65f0f1b5f73fff7252d3e3c33a7ac3d90afa478494a99600226432e55'
FUNCTION_AFTER_SHA='f30c613173c8101ecd81e579e7f8efc493d497dafe6e0ee91de547fc358151ba'
CALL_SUFFIXES=(';$oute', ';if($c', ');Same', ');Same', ');Same', ';$down', ');Same', '))\n $i', '\n if($', ')\n  if', ';if($c', ');$mat', ');Same', ');if($')
CALLS=("Cli ($name+'-status') ('operations status '+$id)", "Cli 'initial-status' 'status'", "Cli ($entry[0]+'-before') $entry[1]", "Cli 'check' 'updates check' 120", "Cli 'available' 'updates status'", "Cli 'download' '--async updates download'", "Cli 'ready' 'updates status'", "Cli 'preinstall-status' 'status'", "Cli 'install' '--async updates install' 120", "Cli 'install-progress' ('operations status '+$installRequest.value.operationId)", "Cli 'post-status' 'status'", "Cli 'recovered-status' 'updates status'", "Cli ($entry[0]+'-after') $entry[1]", "Cli 'quit' 'quit'")

def _sha(text):return hashlib.sha256(text.encode('utf-8')).hexdigest()

def _slots(task,name,function_sha):
 if type(task)is not str or '\x00' in task:raise ValueError('public-cli-task-type')
 start='function '+name+'('
 if task.count(start)!=1:raise ValueError('public-cli-function-count')
 a=task.index(start);z=task.find('\nfunction Ok(',a)
 if z<0 or _sha(task[a:z].rstrip('\n'))!=function_sha:raise ValueError('public-cli-function-beforeimage')
 # Function extent ends at its closing brace, before the blank separator.
 hits=list(re.finditer(r'(?<![\w$])'+re.escape(name)+r'(?![\w])',task))
 if len(hits)!=15 or hits[0].start()!=a+len('function '):raise ValueError('public-cli-name-closure')
 for hit,original,suffix in zip(hits[1:],CALLS,CALL_SUFFIXES):
  expected=name+original[len(OLD):]
  if not task.startswith(expected+suffix,hit.start()):raise ValueError('public-cli-call-beforeimage')
 return [(h.start(),h.end()) for h in hits]

def _replace(task,slots,name):
 for a,z in reversed(slots):task=task[:a]+name+task[z:]
 return task

def derive_graph(function, calls):
 """Rename an exact public function/call AST projection without invoking it."""
 if type(function)is not str or _sha(function)!=FUNCTION_BEFORE_SHA:
  raise ValueError('public-cli-function-beforeimage')
 if type(calls)is not tuple or calls!=CALLS:
  raise ValueError('public-cli-call-beforeimage')
 renamed=function.replace('function '+OLD+'(', 'function '+NEW+'(', 1)
 if _sha(renamed)!=FUNCTION_AFTER_SHA:raise ValueError('public-cli-function-afterimage')
 return renamed,tuple(NEW+call[len(OLD):] for call in calls)

def derive(task):
 if type(task)is not str:raise ValueError('public-cli-task-type')
 if NEW in task:raise ValueError('public-cli-new-name-collision')
 slots=_slots(task,OLD,FUNCTION_BEFORE_SHA)
 a=task.index('function '+OLD+'(');z=task.index('\nfunction Ok(',a)
 function,calls=derive_graph(task[a:z].rstrip('\n'),CALLS)
 out=_replace(task,slots,NEW)
 _slots(out,NEW,FUNCTION_AFTER_SHA)
 if function not in out or any(call not in out for call in calls):raise ValueError('public-cli-graph-inverse')
 if _replace(out,_slots(out,NEW,FUNCTION_AFTER_SHA),OLD)!=task:raise ValueError('public-cli-inverse')
 return out

def inverse(task):
 out=_replace(task,_slots(task,NEW,FUNCTION_AFTER_SHA),OLD)
 if derive(out)!=task:raise ValueError('public-cli-inverse')
 return out
