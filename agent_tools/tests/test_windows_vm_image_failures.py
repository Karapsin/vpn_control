"""Native clone-image failures F3, F3b, F3c, F3d and F3e: whole-before RED, current GREEN.

Each preserved module is the exact windows_vm_image.py that the deploy tool
shipped for a failing template's generalize and capture; the fixture provenance
maps every template and clone operation, and its sha256 is checked at load.
Every test runs one behavioural check on that isolated beforeimage, asserting the
natively observed failure, and the same check on CURRENT, asserting the fix:

* F3: schema 1 never handed sysprep an answer file, so after generalization the
  clone answer stayed on the seed volume and OOBE stopped interactively.
* F3c: the schema-2/3 image answers carried a 705/417-character
  RunSynchronousCommand Path; Setup refuses the whole answer file above 259.
  F3b (schema 2) was the same failure: its recorded cause, overwriting Setup's
  cached answer, is not shown to have run natively, and the 705-character Path
  that Setup refused at parse time fully explains it, so it has no separate
  causal regression.
* F3e: schema 4 ran the fixture setup (initialize.ps1, which registers a
  scheduled task) inside the post-generalize specialize pass, where Task
  Scheduler is not running, so the guest agent was never installed.
* F3d: schemas 4 and 5 generalized templates with sysprep as SYSTEM; every host
  gate accepted, published, listed and selected them. template_evidence_ok is a
  predicate the coordinator applies to a stopped template's disk logs before
  capture; capture does not call it. The guest-side decision (sysprep in the
  Administrator's interactive session and the final step's
  TEMPLATE_SYSPREP_CONTEXT guard) has native evidence only.
* Images published by the failed schema-1 to schema-3 templates are never
  listed, selected or cloned again.

Answer files are parsed as XML. The generated hook, per-clone script and
SetupComplete.cmd are executed by a strict interpreter for exactly the
PowerShell/cmd statements they use (anything else refuses), against a model of
the guest's files. What only Windows proves (Setup's answer-file discovery and
Path limit, Task Scheduler availability, XAML registration, Explorer) stays
covered by the native rounds; the fixture provenance lists those limits.
"""
import base64,builtins,contextlib,copy,hashlib,importlib.machinery,io,json,os,re,subprocess,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from xml.etree import ElementTree as ET
from agent_tools import windows_vm_image as image
from agent_tools import windows_vm_unattend as unattended

FIXTURES=Path(__file__).parent/'fixtures/windows_vm_image_failures'
PROVENANCE=Path(__file__).parent/'fixtures/windows_vm_image_failures/provenance.json'
SCHEMA1=FIXTURES/'windows_vm_image.schema1.py.before.source'
SCHEMA2=FIXTURES/'windows_vm_image.schema2.py.before.source'
SCHEMA3=FIXTURES/'windows_vm_image.schema3.py.before.source'
SCHEMA4=FIXTURES/'windows_vm_image.schema4.py.before.source'
SCHEMA5=FIXTURES/'windows_vm_image.schema5.py.before.source'
# The fixed module under test. The private RED record points this slot at each
# beforeimage so that every GREEN assertion fails for its causal reason.
CURRENT=image

SETUP={'imageName':'Windows 11 Enterprise Evaluation','locale':'en-US','user':'fixtureuser','administrator':'fixtureadmin'}
CREDENTIALS={'user':'A'*24,'administrator':'B'*24}
# Microsoft-Windows-Deployment RunSynchronousCommand Path: at most 259 characters.
PATH_LIMIT=259
NS={'u':'urn:schemas-microsoft-com:unattend'}
WINDIR='C:\\Windows'
SYSPREP=WINDIR+'\\System32\\Sysprep\\sysprep.exe'
PANTHER_ANSWER=WINDIR+'\\Panther\\Unattend\\Unattend.xml'
CACHED_ANSWER=WINDIR+'\\Panther\\unattend.xml'
SETUP_COMPLETE=WINDIR+'\\Setup\\Scripts\\SetupComplete.cmd'
# Native facts (F3e): Task Scheduler is not running in the specialize pass after
# generalization; SetupComplete.cmd runs as SYSTEM once Setup has completed.
TASK_SCHEDULER={'specialize':False,'setup-complete':True}


def isolated(path):
    """One preserved whole module, authenticated by provenance and executed alone."""
    raw=path.read_bytes();record=json.loads(PROVENANCE.read_bytes())['files'][path.name]
    if hashlib.sha256(raw).hexdigest()!=record['sha256']:raise ValueError('before_source_changed')
    return loaded(raw,path.name.split('.')[1],str(path))


def loaded(raw,label,origin):
    """Execute module bytes unregistered; relative imports resolve in agent_tools."""
    module=types.ModuleType('agent_tools._windows_vm_image_'+label.replace('-','_'))
    module.__package__='agent_tools';module.__file__=origin
    module.__spec__=importlib.machinery.ModuleSpec(module.__name__,None,origin=origin)
    exec(compile(raw,origin,'exec'),module.__dict__)
    return module


def shipped(module,name,**remote):
    """The module's own function, run against the names its remote program defines."""
    function=getattr(module,name);scope=dict(vars(module));scope.update(remote)
    return types.FunctionType(function.__code__,scope,function.__name__,function.__defaults__,function.__closure__)


# ---- a strict interpreter for the PowerShell the image tooling generates ----

class PsError(ValueError):
    pass


class PsExit(Exception):
    pass


class Group:
    """Bracketed items; '{' and '@{' bodies are statement lists."""
    def __init__(self,kind,body):self.kind,self.body=kind,body
    def __repr__(self):return 'Group(%r,%r)'%(self.kind,self.body)


_TOKEN=re.compile('|'.join((
    r'(?P<nl>\r?\n|;)',r'(?P<space>[ \t\f]+|`\r?\n)',r'(?P<comment>#[^\r\n]*)',r'(?P<here>@[\'"][ \t]*\r?\n)',
    r"(?P<sq>'(?:[^']|'')*')",r'(?P<dq>"(?:[^"`]|`[\s\S]|"")*")',r'(?P<var>\$(?:env:)?[A-Za-z_][A-Za-z0-9_]*)',
    r'(?P<num>[0-9]+)',r'(?P<param>-[A-Za-z][A-Za-z0-9]*)',r'(?P<minus>-(?=[0-9]))',
    r'(?P<punct>@\(|@\{|::|\+\+|[(){}\[\],|&=+.!<>%*/?:])',r'(?P<word>[A-Za-z_][A-Za-z0-9_.\\:-]*)')))
_MEMBER=re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
_ESCAPES={'0':'\0','a':'\a','b':'\b','f':'\f','n':'\n','r':'\r','t':'\t','v':'\v'}
_OPEN={'(':')','@(':')','[':']','{':'}','@{':'}'}


def _expandable(body):
    """A double-quoted string's value, or None when it would expand a variable."""
    out=[];i=0
    while i<len(body):
        c=body[i]
        if c=='`':out.append(_ESCAPES.get(body[i+1],body[i+1]));i+=2
        elif c=='"':out.append('"');i+=2
        elif c=='$':return None
        else:out.append(c);i+=1
    return ''.join(out)


def ps_tokens(text):
    tokens=[];i=0
    while i<len(text):
        if tokens and tokens[-1]in (('p','.'),('p','::')):
            match=_MEMBER.match(text,i)
            if match:tokens.append(('w',match.group()));i=match.end();continue
        match=_TOKEN.match(text,i)
        if match is None:raise PsError('lex:'+text[i:i+24])
        kind,value=match.lastgroup,match.group();i=match.end()
        if kind=='nl':tokens.append(('nl',None))
        elif kind=='here':
            end=text.find('\n'+value[1]+'@',i-1)
            if end<0:raise PsError('here-string')
            body=text[i:end].rstrip('\r');i=end+3
            tokens.append(('s',body)if value[1]=="'" or '$' not in body else ('x',body))
        elif kind=='sq':tokens.append(('s',value[1:-1].replace("''","'")))
        elif kind=='dq':
            body=_expandable(value[1:-1]);tokens.append(('s',body)if body is not None else ('x',value))
        elif kind=='var':tokens.append(('v',value[1:].lower()))
        elif kind=='num':tokens.append(('n',int(value)))
        elif kind=='param':tokens.append(('a',value[1:].lower()))
        elif kind=='minus':tokens.append(('p','-'))
        elif kind in ('punct','word'):tokens.append(('p' if kind=='punct' else 'w',value))
    return tokens


def _statements(items):
    statements=[[]]
    for item in items:
        if item==('nl',None):statements.append([])
        else:statements[-1].append(item)
    return [statement for statement in statements if statement]


def ps_parse(text):
    tokens=ps_tokens(text);position=0
    def items(close):
        nonlocal position
        sequence=[]
        while position<len(tokens):
            token=tokens[position];position+=1
            if token==('p',close):return sequence
            if token[0]=='p' and token[1]in _OPEN:
                body=items(_OPEN[token[1]])
                sequence.append(Group(token[1],_statements(body)if token[1]in ('{','@{') else [t for t in body if t!=('nl',None)]))
            elif token[0]=='p' and token[1]in (')',']','}'):raise PsError('unbalanced '+token[1])
            else:sequence.append(token)
        if close is not None:raise PsError('unclosed '+close)
        return sequence
    return _statements(items(None))


def ps_commands(text):
    """Commands a script invokes: the word starting each statement or pipeline element."""
    found=set()
    def walk(items):
        start=True
        for item in items:
            if isinstance(item,Group):
                for part in (item.body if item.kind in ('{','@{') else [item.body]):walk(part)
                start=False;continue
            if start and item[0]=='w':found.add(item[1].lower())
            start=item in (('p','|'),('p','='),('p','&'),('p',','))
    for statement in ps_parse(text):walk(statement)
    return found


def _is(item,kind):
    return type(item)is tuple and item[0]==kind


def _word(item,*names):
    return _is(item,'w') and item[1].lower()in names


def _assignment(statement):
    return type(statement[0])is tuple and statement[0][0]=='v' and len(statement)>2 and statement[1]==('p','=')


def _split(items,separator):
    parts=[[]]
    for item in items:
        if item==separator:parts.append([])
        else:parts[-1].append(item)
    return parts


class Ps:
    """Evaluate generated PowerShell against a guest; unknown statements refuse.

    Locate mode only evaluates assignments, Start-Process and
    [IO.File]::WriteAllText wherever they are evaluable, to read the sysprep
    invocation and the answer-file write out of the large generalize scripts.
    """
    COMMANDS=('join-path','get-volume','new-item','md','copy-item','cp','start-process')
    SWITCHES={'force','wait','passthru','noclobber'}

    def __init__(self,guest,phase,root=None,stdin=None,locate=False):
        self.guest,self.phase,self.stdin,self.locate=guest,phase,stdin,locate
        self.vars={'env:windir':WINDIR,'psscriptroot':root,'true':True,'false':False,'null':None}

    def run(self,text):
        statements=ps_parse(text)
        if not self.locate:
            try:self.block(statements)
            except PsExit:pass
            return
        def walk(block):
            for statement in block:
                yield statement
                for item in statement:
                    if isinstance(item,Group)and item.kind=='{':yield from walk(item.body)
        for statement in walk(statements):
            head=statement[0]
            try:
                if _assignment(statement):
                    self.vars.pop(head[1],None);self.vars[head[1]]=self.value(statement[2:])
                elif _word(head,'start-process') or isinstance(head,Group)and head.kind=='[' and statement[2:3]==[('w','WriteAllText')]:
                    self.value(statement)
            except (ValueError,IndexError):continue

    def block(self,statements):
        for statement in statements:self.statement(statement)

    def statement(self,s):
        head=s[0]
        if _assignment(s):self.vars[head[1]]=self.value(s[2:]);return
        if _word(head,'if'):
            if len(s)!=3 or not all(isinstance(g,Group)for g in s[1:]):raise PsError('if form')
            if self.truth(self.value(s[1].body)):self.block(s[2].body)
            return
        if _word(head,'foreach'):
            header=s[1].body if len(s)==3 and isinstance(s[1],Group)else []
            if len(header)<3 or not _is(header[0],'v') or not _word(header[1],'in'):raise PsError('foreach form')
            values=self.value(header[2:])
            if type(values)is not list:raise PsError('foreach values')
            for item in values:self.vars[header[0][1]]=item;self.block(s[2].body)
            return
        if _word(head,'exit'):
            if len(s)!=2 or not _is(s[1],'n'):raise PsError('exit form')
            self.guest.exits.append((self.phase,s[1][1]));raise PsExit(s[1][1])
        if head==('p','&'):
            path=self.value(s[1:])
            if type(path)is not str:raise PsError('call operator')
            self.guest.run_file(path,self.phase);return
        self.value(s)

    def truth(self,value):
        if type(value)not in (bool,int):raise PsError('condition')
        return bool(value)

    def value(self,items):
        stages=_split(items,('p','|'))
        if _word(stages[0][0]if stages[0]else None,*self.COMMANDS):result=self.command(stages[0][0][1].lower(),stages[0][1:])
        else:result=self.expression(stages[0])
        for stage in stages[1:]:
            if len(stage)==1 and _word(stage[0],'out-null'):result=None
            elif len(stage)==1 and _word(stage[0],'convertfrom-json'):result=json.loads(result)
            elif len(stage)==4 and _word(stage[0],'where-object')and _is(stage[1],'w') and stage[2]==('a','eq'):
                wanted=self.expression([stage[3]]);result=[row for row in result if self.member(row,stage[1][1])==wanted]
            else:raise PsError('pipeline')
        return result

    def expression(self,items):
        for operator in ('eq','ne'):
            if ('a',operator)in items:
                k=items.index(('a',operator));left,right=self.expression(items[:k]),self.expression(items[k+1:])
                same=left.lower()==right.lower()if type(left)is str and type(right)is str else left==right
                return same if operator=='eq' else not same
        for k in range(len(items)-1,0,-1):
            if items[k]in (('p','+'),('p','-')):
                left,right=self.expression(items[:k]),self.expression(items[k+1:])
                if items[k][1]=='+' and type(left)is type(right)and type(left)in (str,int):return left+right
                if items[k][1]=='-' and type(left)is int and type(right)is int:return left-right
                raise PsError('operands')
        return self.postfix(items)

    def postfix(self,items):
        if not items:raise PsError('empty expression')
        value,rest=self.primary(items)
        while rest:
            if rest[0]==('p','.') and len(rest)>1 and _is(rest[1],'w'):value=self.member(value,rest[1][1]);rest=rest[2:]
            elif isinstance(rest[0],Group)and rest[0].kind=='[' and type(value)is list:value=value[self.expression(rest[0].body)];rest=rest[1:]
            else:raise PsError('expression')
        return value

    def primary(self,items):
        head=items[0]
        if isinstance(head,Group):
            if head.kind=='(':return self.value(head.body),items[1:]
            if head.kind=='@(':
                parts=[part for part in _split(head.body,('p',','))if part]
                values=[self.value(part)for part in parts]
                return (values[0]if len(values)==1 and type(values[0])is list else values),items[1:]
            if head.kind=='[' and items[1:2]==[('p','::')] and len(items)>2:return self.static(head,items[2:])
            raise PsError('group '+head.kind)
        if type(head)is not tuple:raise PsError('primary')
        kind,value=head
        if kind=='s':return value,items[1:]
        if kind=='n':return value,items[1:]
        if kind=='v':
            if value not in self.vars:raise PsError('variable '+value)
            return self.vars[value],items[1:]
        raise PsError('primary %r'%(head,))

    def static(self,type_group,rest):
        if not all(_is(t,'w')for t in type_group.body)or not _is(rest[0],'w'):raise PsError('type literal')
        name=''.join(t[1]for t in type_group.body).lower();member=rest[0][1].lower()
        args=rest[1]if len(rest)>1 and isinstance(rest[1],Group)and rest[1].kind=='(' else None
        if (name,member)==('io.file','writealltext')and args is not None:
            values=[self.value(part)for part in _split(args.body,('p',','))]
            if len(values)!=3 or type(values[0])is not str or type(values[1])is not str:raise PsError('WriteAllText')
            self.guest.write(values[0],values[1],self.phase);return None,rest[2:]
        if (name,member)==('text.encoding','ascii'):return 'ascii',rest[1:]
        if (name,member)==('text.utf8encoding','new')and args is not None:return 'utf8',rest[2:]
        if (name,member)==('console','in')and rest[1:3]==[('p','.'),('w','ReadToEnd')]and len(rest)>3 and isinstance(rest[3],Group)and not rest[3].body:
            if self.stdin is None:raise PsError('stdin')
            return self.stdin,rest[4:]
        raise PsError('static %s::%s'%(name,member))

    def member(self,value,name):
        if type(value)is dict:
            found=[v for k,v in value.items()if k.lower()==name.lower()]
            if len(found)!=1:raise PsError('member '+name)
            return found[0]
        if type(value)is list and name.lower()=='count':return len(value)
        raise PsError('member '+name)

    def argument(self,items,k):
        """One command-mode argument starting at items[k]; returns (value, next index)."""
        item=items[k]
        if type(item)is tuple and item[0]=='w':return item[1],k+1
        end=k+1
        while end<len(items) and (items[end]==('p','.') or isinstance(items[end],Group)and items[end].kind=='['):
            end+=2 if items[end]==('p','.') else 1
        return self.postfix(items[k:end]),end

    def command(self,name,items):
        named,positional,k={},[],0
        while k<len(items):
            if type(items[k])is tuple and items[k][0]=='a':
                key=items[k][1]
                if key in self.SWITCHES:named[key]=True;k+=1
                else:named[key],k=self.argument(items,k+1)
            else:
                value,k=self.argument(items,k);positional.append(value)
        def one(*keys,index=None):
            values=[named[key]for key in keys if key in named]+([positional[index]]if index is not None and index<len(positional)else [])
            if len(values)!=1:raise PsError(name+' arguments')
            return values[0]
        if name=='join-path':return join(one('path',index=0),one('childpath',index=1))
        if name=='get-volume':
            label=named.get('filesystemlabel')
            return [dict(v)for v in self.guest.volumes if label is None or v['filesystemlabel'].lower()==label.lower()]
        if name in ('new-item','md'):
            if name=='new-item' and str(named.get('itemtype','')).lower()!='directory':raise PsError('New-Item type')
            self.guest.mkdir(one('path',index=0),self.phase);return None
        if name in ('copy-item','cp'):
            self.guest.copy(one('literalpath','path',index=0),one('destination',index=1),self.phase);return None
        if name=='start-process':
            arguments=named.get('argumentlist',[])
            if type(arguments)is not list or not all(type(a)is str for a in arguments):raise PsError('Start-Process arguments')
            self.guest.processes.append((one('filepath',index=0),arguments));return None
        raise PsError('command '+name)


def join(parent,child):
    return parent.rstrip('\\')+'\\'+child.lstrip('\\')


def command_line(line):
    """Windows command-line arguments (CommandLineToArgvW quoting)."""
    args,current,quoted,started,i=[],[],False,False,0
    while i<len(line):
        c=line[i]
        if c=='\\':
            j=i
            while j<len(line)and line[j]=='\\':j+=1
            if j<len(line)and line[j]=='"':
                current.append('\\'*((j-i)//2))
                if (j-i)%2:current.append('"');i=j+1
                else:i=j
            else:current.append(line[i:j]);i=j
            started=True;continue
        if c=='"':
            if quoted and line[i+1:i+2]=='"':current.append('"');i+=2;continue
            quoted=not quoted;started=True;i+=1;continue
        if c in ' \t' and not quoted:
            if started:args.append(''.join(current));current,started=[],False
            i+=1;continue
        current.append(c);started=True;i+=1
    if started:args.append(''.join(current))
    return args


def powershell_cli(args):
    """('command', text) or ('file', path) for powershell.exe's own switches."""
    i=0
    while i<len(args):
        switch=args[i].lower()
        if switch in ('-noprofile','-nop','-noninteractive','-noni'):i+=1
        elif switch in ('-executionpolicy','-ep','-exec'):i+=2
        elif switch in ('-command','-c'):return 'command',' '.join(args[i+1:])
        elif switch in ('-file','-f')and i+2==len(args):return 'file',args[i+1]
        else:raise PsError('powershell switch '+switch)
    raise PsError('powershell without a command')


class Guest:
    """A generalized clone's files and runs as Setup's passes reach them."""
    def __init__(self,seed=None,drive='E'):
        self.files,self.dirs,self.processes,self.runs,self.writes,self.exits={},set(),[],[],[],[]
        for path in ('C:\\','C:\\Windows','C:\\Windows\\Panther','C:\\Windows\\Setup',drive+':\\'):self.dirs.add(self.key(path))
        self.volumes=[{'filesystemlabel':'VCSETUP','driveletter':drive}]
        self.agent_task=None;self.setup_error=None
        for name,item in (seed or {}).items():self.files[self.key(drive+':\\'+name)]=item

    @staticmethod
    def key(path):
        if type(path)is not str:raise PsError('path')
        return re.sub(r'\\+',r'\\',path.replace('/','\\')).rstrip('\\').upper()

    def parent(self,path):
        return self.key(path).rsplit('\\',1)[0]

    def mkdir(self,path,phase):
        key=self.key(path)
        while '\\' in key:self.dirs.add(key);key=key.rsplit('\\',1)[0]

    def write(self,path,content,phase,kind=None):
        if self.parent(path)not in self.dirs:raise PsError('missing folder for '+path)
        self.files[self.key(path)]=(kind or self.kind_of(path),content);self.writes.append((phase,self.key(path)))

    @staticmethod
    def kind_of(path):
        return 'cmd' if path.lower().endswith('.cmd') else 'data'

    def copy(self,source,destination,phase):
        if self.key(source)not in self.files:raise PsError('missing '+source)
        if self.key(destination)in self.dirs:destination=join(destination,source.replace('/','\\').rsplit('\\',1)[-1])
        if self.parent(destination)not in self.dirs:raise PsError('missing folder for '+destination)
        self.files[self.key(destination)]=self.files[self.key(source)];self.writes.append((phase,self.key(destination)))

    def run_file(self,path,phase):
        item=self.files.get(self.key(path))
        if item is None:raise PsError('missing script '+path)
        kind,content=item;self.runs.append((phase,self.key(path).rsplit('\\',1)[-1].lower()))
        if kind=='script':Ps(self,phase,root=path.rsplit('\\',1)[0]).run(content)
        elif kind=='fixture-setup':
            # The unchanged fixture setup: it registers the agent installation as a
            # scheduled task, which needs the Task Scheduler service.
            needs='register-scheduledtask' in ps_commands(content)
            self.agent_task='registered' if TASK_SCHEDULER[phase] or not needs else 'task-scheduler-not-running'
        else:raise PsError('not executable '+path)

    def command_line(self,line,phase):
        args=command_line(line)
        if not args or args[0].lower()!='powershell.exe':raise PsError('program '+line[:40])
        mode,value=powershell_cli(args[1:])
        if mode=='file':self.run_file(value,phase)
        else:Ps(self,phase).run(value)

    def run_cmd(self,path,phase):
        kind,content=self.files[self.key(path)]
        if kind!='cmd':raise PsError('not a batch file')
        folder=path.rsplit('\\',1)[0]+'\\'
        for line in content.splitlines():
            line=line.strip()
            if not line or line.lower()=='@echo off':continue
            line=re.sub('(?i)%windir%',lambda m:WINDIR,line.replace('%~dp0',folder))
            if '%' in line:raise PsError('cmd variable')
            args=command_line(line);words=[]
            while args:
                arg=args.pop(0)
                if arg=='>':args.pop(0)
                elif arg!='2>&1':words.append(arg)
            if words and words[0].lower()=='powershell.exe':
                mode,value=powershell_cli(words[1:])
                if mode!='file':raise PsError('cmd powershell')
                self.run_file(value,phase)
            elif words and words[0].lower()=='del' and words[1:-1]==['/f','/q']:
                self.files.pop(self.key(words[-1]),None);self.writes.append((phase,'deleted:'+self.key(words[-1])))
            else:raise PsError('cmd statement '+line[:40])


def run_synchronous_paths(answer,setting_pass):
    commands=ET.fromstring(answer.encode('utf-8')if type(answer)is str else answer).findall(".//u:settings[@pass='"+setting_pass+"']//u:RunSynchronousCommand",NS)
    return [command.find('u:Path',NS).text for command in sorted(commands,key=lambda c:int(c.find('u:Order',NS).text))]


def oobe_accounts(answer):
    root=ET.fromstring(answer.encode('utf-8'))
    return sorted(node.text for node in root.findall(".//u:settings[@pass='oobeSystem']//u:LocalAccount/u:Name",NS))


def clone_seed(module):
    """The clone start's VCSETUP volume: the unchanged fixture answer and setup,
    plus the image module's per-clone script when that module ships one."""
    seed={'Autounattend.xml':('answer',unattended.answer_file(SETUP,CREDENTIALS).decode('utf-8')),
          'initialize.ps1':('fixture-setup',unattended.INITIALIZE),'install-agent.ps1':('fixture-agent',unattended.INSTALL_AGENT)}
    if hasattr(module,'CLONE_SPECIALIZE'):seed['clone-specialize.ps1']=('script',module.CLONE_SPECIALIZE)
    return seed


def clone_first_boot(module,sysprep_answer):
    """Setup's passes on a clone of a template generalized with sysprep_answer."""
    seed=clone_seed(module);guest=Guest(seed)
    paths={'image':run_synchronous_paths(sysprep_answer,'specialize')if sysprep_answer is not None else [],
           'clone':run_synchronous_paths(seed['Autounattend.xml'][1],'specialize')}
    if any(len(path)>PATH_LIMIT for path in paths['image']):guest.setup_error='answer-file-refused'
    else:
        for path in paths['image']:guest.command_line(path,'specialize')
    found=guest.files.get(guest.key(PANTHER_ANSWER))if guest.setup_error is None else None
    oobe=None if found is None else 'clone' if found==seed['Autounattend.xml'] else 'other'
    if guest.setup_error is None and guest.key(SETUP_COMPLETE)in guest.files:guest.run_cmd(SETUP_COMPLETE,'setup-complete')
    return {'pathLengths':{name:[len(p)for p in values]for name,values in paths.items()},'setupError':guest.setup_error,'oobeAnswer':oobe,
            'oobeAccounts':oobe_accounts(found[1])if oobe=='clone' else None,
            'specializeScripts':[name for phase,name in guest.runs if phase=='specialize'],
            'initializePhases':[phase for phase,name in guest.runs if name=='initialize.ps1'],'agentInstallTask':guest.agent_task,
            'cachedAnswerWritten':any(key==guest.key(CACHED_ANSWER)for phase,key in guest.writes),
            'cloneAnswerOnDiskAfterSetup':guest.key(PANTHER_ANSWER)in guest.files,'exits':guest.exits}


@contextlib.contextmanager
def linux_host():
    """The generalize host's boot id and clock, as the deployed program sees them."""
    real=builtins.open
    def opened(path,*args,**kwargs):return io.StringIO('FIXTURE_BOOT')if str(path)=='/proc/sys/kernel/random/boot_id' else real(path,*args,**kwargs)
    clock=iter(range(0,10**6,7))
    with mock.patch.object(builtins,'open',side_effect=opened),mock.patch('time.sleep'),mock.patch('time.monotonic',side_effect=lambda:next(clock)):yield


def generalize(module,result=None):
    """Run the module's generalize_instance once; returns (state or refusal, guest script, stdin payload).

    result(operation) is the setup step's one-line result; None keeps it running.
    """
    operation=str(uuid.uuid4());records={'qemu-started.json':{'pid':11,'startTicks':5},'swtpm-started.json':{'pid':12,'startTicks':4}};sent=[]
    with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as folder:
        root=Path(folder);(root/'qga.sock').write_bytes(b'')
        def read(name):
            if name not in records:raise FileNotFoundError(name)
            return copy.deepcopy(records[name])
        def save(name,value):
            with (root/name).open('xb')as stream:stream.write(value if type(value)is bytes else json.dumps(value).encode())
            if type(value)is not bytes:records[name]=copy.deepcopy(value)
        def call(path,command,arguments,**kwargs):
            if command=='guest-exec':sent.append(arguments);return {'pid':4242}
            if result is None:return {'exited':False}
            return {'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(result(operation)).encode()).decode()}
        qualify=lambda *args:{'state':'setup-observed','setupReady':True,'result':{'os':{'build':'26200'}}}
        remote={'CONTEXT':{'hostBootId':'FIXTURE_BOOT'},'call':call,'qualify_instance':qualify,'GENERALIZE_SCRIPT':module.generalize_source(SETUP,operation),
                'GENERALIZE_CHECK_SCRIPT':'FIXED_CHECK','GENERALIZE_PROBE_TEMPLATE':module.probe_template(),'_actor_absent':lambda row,process,birth:False}
        if hasattr(module,'image_answer_file'):remote['IMAGE_ANSWER']=module.image_answer_file(SETUP)
        function=shipped(module,'generalize_instance',**remote)
        with linux_host():
            try:state=function({},SETUP,operation,False,root,read,save,lambda row:None,lambda *a:None,lambda:None,lambda:None,lambda:{'guestAgentReady':False},lambda pid:0)['state']
            except ValueError as error:state=str(error)
    if len(sent)!=1:raise AssertionError('one guest submission expected')
    script=base64.b64decode(sent[0]['arg'][-1]).decode('utf-16le');payload=json.loads(base64.b64decode(sent[0]['input-data']))
    return state,script,payload


def sysprep_answer(module):
    """The answer file the template's sysprep receives, from what generalize sends."""
    _,script,payload=generalize(module)
    setup=Guest();setup.write=lambda path,content,phase:setup.files.__setitem__(Guest.key(path),content)
    Ps(setup,'template',stdin=json.dumps(payload),locate=True).run(script)
    final=Guest();Ps(final,'template',locate=True).run(payload['finalScript'])
    runs=[args for path,args in final.processes if Guest.key(path)==Guest.key(SYSPREP)]
    if len(runs)!=1:raise AssertionError('one sysprep invocation expected: %r'%runs)
    answers=[arg.split(':',1)[1]for arg in runs[0]if arg.lower().startswith('/unattend:')]
    if not answers:return runs[0],None
    return runs[0],setup.files[Guest.key(answers[0])]


class CloneAnswerDeliveryTests(unittest.TestCase):
    @unittest.skipUnless(os.name=='posix','generalize_instance opens O_NOFOLLOW wire files as on its Linux host')
    def test_f3_clone_answer_reaches_oobe_only_through_the_sysprep_answer_hook(self):
        """F3 (clone d2a8f909, schema-1 image 21b57093): OOBE stopped interactively."""
        schema1=isolated(SCHEMA1);old_args,old_answer=sysprep_answer(schema1);old=clone_first_boot(schema1,old_answer)
        # RED: sysprep ran without an answer file; the clone answer never left the seed volume.
        self.assertIn('/generalize',old_args);self.assertIsNone(old_answer)
        self.assertEqual((None,None,[]),(old['oobeAnswer'],old['oobeAccounts'],old['specializeScripts']))
        args,answer=sysprep_answer(CURRENT);new=clone_first_boot(CURRENT,answer)
        self.assertIsNotNone(answer,args);self.assertIsNone(new['setupError'])
        # GREEN: the fixed sysprep answer's specialize hook places the clone answer where
        # oobeSystem discovers it; Setup's cached answer file is never written.
        self.assertEqual('clone',new['oobeAnswer']);self.assertEqual(['fixtureadmin','fixtureuser'],new['oobeAccounts'])
        self.assertFalse(new['cachedAnswerWritten'],'the hook wrote Setup cached '+CACHED_ANSWER)
        for forbidden in ('LocalAccount','AutoLogon','Password'):self.assertNotIn(forbidden,answer)


class RunSynchronousPathTests(unittest.TestCase):
    def test_f3c_every_run_synchronous_path_fits_the_windows_limit(self):
        """F3c (clone 545113da, schema 3) and F3b's native failure (clone f5584e4c, schema 2)."""
        for label,path,longest in (('schema2',SCHEMA2,705),('schema3',SCHEMA3,417)):
            with self.subTest(before=label):
                old_module=isolated(path);old=clone_first_boot(old_module,old_module.image_answer_file(SETUP))
                # RED: Setup refuses the whole image answer file before its hook can run.
                self.assertEqual(longest,max(old['pathLengths']['image']))
                self.assertEqual(('answer-file-refused',None,[]),(old['setupError'],old['oobeAnswer'],old['specializeScripts']))
        # Calibration: schema 4's 247-character hook passed specialize natively (round 4 applied the clone accounts).
        schema4=isolated(SCHEMA4);calibrated=clone_first_boot(schema4,schema4.image_answer_file(SETUP))
        self.assertEqual(([247],None,'clone'),(calibrated['pathLengths']['image'],calibrated['setupError'],calibrated['oobeAnswer']))
        new=clone_first_boot(CURRENT,CURRENT.image_answer_file(SETUP))
        lengths=new['pathLengths']['image']+new['pathLengths']['clone']
        # GREEN: every RunSynchronous Path of the image and clone answers fits.
        self.assertTrue(new['pathLengths']['image']);self.assertLessEqual(max(lengths),PATH_LIMIT,new['pathLengths'])
        self.assertEqual((None,'clone'),(new['setupError'],new['oobeAnswer']))
        # The limit holds for a RunSynchronousCommand in any pass, not only specialize.
        for answer in (CURRENT.image_answer_file(SETUP),unattended.answer_file(SETUP,CREDENTIALS)):
            raw=answer.encode('utf-8')if type(answer)is str else answer
            paths=[node.text for node in ET.fromstring(raw).findall('.//u:RunSynchronousCommand/u:Path',NS)]
            self.assertTrue(paths);self.assertLessEqual(max(map(len,paths)),PATH_LIMIT,paths)


class SpecializeTaskSchedulerTests(unittest.TestCase):
    def test_f3e_fixture_setup_runs_from_setupcomplete_not_in_specialize(self):
        """F3e (clone f7619b39, schema-4 image 0a762488): Register-ScheduledTask 0x80041315."""
        self.assertIn('register-scheduledtask',ps_commands(unattended.INITIALIZE))
        schema4=isolated(SCHEMA4);old=clone_first_boot(schema4,schema4.image_answer_file(SETUP))
        # RED: the hook delivered the clone answer (as observed natively) but ran the
        # fixture setup inside specialize, where its scheduled task cannot be registered.
        self.assertEqual(('clone',['fixtureadmin','fixtureuser']),(old['oobeAnswer'],old['oobeAccounts']))
        self.assertEqual((['initialize.ps1'],['specialize'],'task-scheduler-not-running'),(old['specializeScripts'],old['initializePhases'],old['agentInstallTask']))
        new=clone_first_boot(CURRENT,CURRENT.image_answer_file(SETUP))
        # GREEN: specialize only stages; SetupComplete.cmd runs the unchanged setup after
        # Setup, then removes the clone answer with its passwords.
        self.assertNotIn('initialize.ps1',new['specializeScripts']);self.assertEqual(['setup-complete'],new['initializePhases'])
        self.assertEqual(('registered','clone',False),(new['agentInstallTask'],new['oobeAnswer'],new['cloneAnswerOnDiskAfterSetup']))


# ---- F3d host gates ----

BOOT='3e7c1a52-0d4b-4f6e-9a21-6b8f0c5d2e14'


def spec_dict(root,deployment=None):
    asset=lambda name,size:{'path':'/fixture/media/'+name,'sha256':hashlib.sha256(name.encode()).hexdigest(),'bytes':size}
    return {'deploymentId':deployment or str(uuid.uuid4()),'host':'fixture-host','root':str(root),'cpus':4,'memoryMiB':4096,'diskGiB':64,'headroomMiB':8192,'vncPort':5963,
            'assets':{'installer':asset('windows-x64.iso',7092807680),'drivers':asset('virtio-win.iso',789645312),
                      'firmwareCode':{'path':'/fixture/OVMF_CODE.secboot.4m.fd','sha256':'c'*64,'bytes':3653632},
                      'firmwareVars':{'path':'/fixture/OVMF_VARS.4m.fd','sha256':'d'*64,'bytes':540672}}}


def system_setup_result(module,operation):
    """What the schema-4/5 setup step reported: sysprep armed as SYSTEM (S-1-5-18)."""
    return {'nonce':operation,'principal':'S-1-5-18','accountsRemoved':[SETUP['user'],SETUP['administrator']],'sessionsSignedOut':True,
            'automaticLogonDisabled':True,'setupStateRemoved':True,'setupCachesRemoved':True,'volumeDecryptionStarted':True,
            'finalSha256':module.GENERALIZE_FINAL_SHA256,'finalScheduled':True}


def administrator_setup_result(module,operation):
    """The schema-6 setup step's result: sysprep armed in the Administrator's session."""
    return {'nonce':operation,'sysprepPrincipal':'builtin-administrator-interactive','accountsRemoved':[SETUP['user'],SETUP['administrator']],
            'temporaryAccountsRemoved':['defaultuser0'],'temporaryAccountsDeferred':[],'sessionsSignedOut':True,'fixtureAutomaticLogonRemoved':True,
            'setupStateRemoved':True,'setupCachesRemoved':True,'volumeDecryptionStarted':True,'finalSha256':module.GENERALIZE_FINAL_SHA256,
            'finalScheduled':True,'restartScheduled':True}


def capture(module,home,setup_result):
    """Run the module's capture_image_instance on a stopped template whose
    generalize terminal holds setup_result; returns its state or refusal."""
    root=home/('vc-rw-'+uuid.uuid4().hex[:8]);root.mkdir(mode=0o700);(root/'tpm').mkdir(mode=0o700)
    for name,raw in (('disk.qcow2',b'QFI\xfb'+b'\0'*60),('uefi-vars.fd',b'VARS'*16),('tpm/tpm2-00.permall',b'TPM2'*32)):
        (root/name).write_bytes(raw);(root/name).chmod(0o600)
    spec=spec_dict(root);identity=lambda name:(lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid])(os.lstat(root/name))
    records={'generalize-stopped.json':{'operationId':'g'},'generalize-intent.json':{'operationId':'g','os':{'build':'26200'}},
             'generalize.terminal.json':{'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(setup_result(module,'g')).encode()).decode()},
             'qemu-started.json':{'pid':11,'argv':['/proc/self/fd/9','-netdev','user,id=net0,restrict=on','-device','virtio-net-pci,netdev=net0']},
             'swtpm-started.json':{'pid':12},'mutable-artifacts.json':{name:identity(name)for name in ('disk.qcow2','uefi-vars.fd')},
             'installer-image.json':{'installerSha256':spec['assets']['installer']['sha256'],'image':{'name':SETUP['imageName']}}}
    def save(name,value):
        with (root/name).open('xb')as stream:stream.write(json.dumps(value).encode())
        records[name]=value
    def qemu_img(argv,**kwargs):
        if argv[1]=='check':return subprocess.CompletedProcess(argv,0,json.dumps({'check-errors':0}).encode(),b'')
        return subprocess.CompletedProcess(argv,0,json.dumps({'format':'qcow2','virtual-size':64*1024**3}).encode(),b'')
    function=shipped(module,'capture_image_instance',CONTEXT={'hostBootId':BOOT,'pending':[]},SPEC=spec,SETUP=SETUP,_actor_absent=lambda row,process,birth:True)
    with mock.patch('subprocess.run',side_effect=qemu_img):
        try:return function(spec,SETUP,str(uuid.uuid4()),root,lambda name:copy.deepcopy(records[name]),save,lambda row:None,lambda pid:0,{'qemu-img':5}),spec
        except ValueError as error:return {'state':'refused','reason':str(error)},spec


def listing(module,home):
    out=io.StringIO()
    with contextlib.redirect_stdout(out):shipped(module,'images_main',SPEC=spec_dict(home/'vc-rw-list'))()
    return json.loads(out.getvalue())


def clone_start_admits(module,home,row,spec):
    """The clone start's admission: read_image plus clone_manifest_matches."""
    try:manifest,_=module.read_image(home/module.STORE_NAME,row['imageId'],row['manifestSha256'])
    except (OSError,ValueError,KeyError,TypeError)as error:return 'refused:'+(str(error)if type(error)is ValueError else type(error).__name__)
    return module.clone_manifest_matches(manifest,spec,SETUP,{'name':SETUP['imageName']})


def template_logs(**changes):
    """A read-only disk-logs observation of a template stopped by its own sysprep."""
    work='Windows/Temp/VpnControlGeneralize/'
    context={'sid':'S-1-5-21-1-2-3-500','elevated':True,'sessionId':1,'bootUnixMs':2000,'setupUnixMs':1000,
             'temporaryAccountsRemoved':['defaultuser0'],'usersFolder':['Administrator','Public']}
    context.update(changes.pop('context',{}))
    files={work+'final-context.json':{'bytes':1,'tail':json.dumps(context,indent=4).splitlines(),'errors':[]},
           work+'final.log':{'bytes':1,'tail':['\ufeff**********************','Windows PowerShell transcript start','Username: DESKTOP-1\\Administrator',
                                                'RunAs User: DESKTOP-1\\Administrator','Machine: DESKTOP-1 (Microsoft Windows NT 10.0.26200.0)'],'errors':[]},
           work+'failure.json':None,'listings':{'Users':['Administrator/','All Users@','Default User@','Default/','Public/','desktop.ini']}}
    files.update(changes.pop('files',{}))
    presence={'Windows/Panther/Unattend/Unattend.xml':None,'Windows/Panther/unattend.xml':3703,'Windows/System32/Sysprep/Sysprep_succeeded.tag':0}
    value={'schemaVersion':1,'mode':'disk-logs','state':'disk-logs-observed','logs':{'files':files,'presence':presence}}
    value.update(changes);return value


SYSTEM_EVIDENCE={'system-sid':{'context':{'sid':'S-1-5-18'}},'session-0':{'context':{'sessionId':0}},
                 'boot-not-after-setup':{'context':{'bootUnixMs':900}},
                 'system-transcript':{'files':{'Windows/Temp/VpnControlGeneralize/final.log':{'bytes':1,'tail':['Username: WORKGROUP\\SYSTEM','RunAs User: WORKGROUP\\SYSTEM'],'errors':[]}}}}


def system_template_gates(module,home,published):
    """Every host gate's decision for a template whose sysprep was armed as SYSTEM.

    published is the listing row of such a template's image, captured by the
    unfixed tooling into home's store."""
    seen={'generalize':generalize(module,lambda operation:system_setup_result(module,operation))[0]}
    with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as other:
        result,_=capture(module,Path(other),system_setup_result);seen['capture']=result.get('reason',result['state'])
    rows=listing(module,home);spec=spec_dict(home/'vc-rw-select');now=published['manifest']['createdAtUnixMs']+60_000
    seen['listed']=[row['imageId']for row in rows['images']];seen['refusedImages']=rows['refusedImages']
    chosen=module.choose_image(rows,spec,SETUP,now);seen['selected']=chosen and chosen['imageId']
    unfixed={'state':'images-observed','images':[published]}
    chosen=module.choose_image(unfixed,spec,SETUP,now);seen['selectedFromUnfixedListing']=chosen and chosen['imageId']
    seen['cloneStart']=clone_start_admits(module,home,published,spec)
    gate=getattr(module,'template_evidence_ok',None)
    seen['evidence']=None if gate is None else {name:gate(template_logs(**copy.deepcopy(change)),SETUP)for name,change in SYSTEM_EVIDENCE.items()}
    return seen


@unittest.skipUnless(os.name=='posix','capture and listing check POSIX owners, modes and O_NOFOLLOW like their Linux host')
class SystemContextTemplateTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(folder.cleanup)
        self.home=Path(folder.name)
        def writable():
            for path in sorted(self.home.rglob('*'),reverse=True):
                if path.is_dir()and not path.is_symlink():path.chmod(0o700)
        self.addCleanup(writable)

    def test_f3d_host_gates_refuse_a_template_generalized_as_system(self):
        """F3d (clones f7619b39 and ee0d45b1): templates generalized by SYSTEM-context sysprep."""
        for label,path in (('schema4',SCHEMA4),('schema5',SCHEMA5)):
            with self.subTest(before=label):
                home=self.home/label;home.mkdir()
                old=isolated(path);result,_=capture(old,home,system_setup_result)
                self.assertEqual('image-captured',result['state'],result)
                published=[row for row in listing(old,home)['images']if row['imageId']==result['imageId']][0]
                before=system_template_gates(old,home,published)
                # RED: the unfixed gates accepted, published, listed, selected and admitted
                # the SYSTEM template, and no disk-evidence gate existed.
                self.assertEqual({'generalize':'generalize-submitted','capture':'image-captured','listed':[result['imageId']],'refusedImages':0,
                                  'selected':result['imageId'],'selectedFromUnfixedListing':result['imageId'],'cloneStart':True,'evidence':None},before)
                after=system_template_gates(CURRENT,home,published)
                # GREEN: each gate refuses the SYSTEM template on its own.
                with self.subTest(gate='generalize'):self.assertEqual('instance_generalize_result',after['generalize'])
                with self.subTest(gate='capture'):self.assertEqual('instance_capture_sysprep_context',after['capture'])
                with self.subTest(gate='listing'):self.assertEqual(([],1),(after['listed'],after['refusedImages']))
                with self.subTest(gate='selection'):self.assertEqual((None,None),(after['selected'],after['selectedFromUnfixedListing']))
                with self.subTest(gate='clone-start'):self.assertIn(after['cloneStart'],('refused:instance_image_directory','refused:instance_image_manifest'))
                with self.subTest(gate='disk-evidence'):self.assertEqual({name:False for name in SYSTEM_EVIDENCE},after['evidence'])

    def test_f3d_controls_show_each_current_refusal_is_the_sysprep_context(self):
        """Control, not causal: a different, Administrator-shaped result (the schema-6
        setup step's) passes every current gate, and changing only its sysprep
        principal or only its restart makes generalize and capture refuse again."""
        self.assertEqual('generalize-submitted',generalize(CURRENT,lambda operation:administrator_setup_result(CURRENT,operation))[0])
        result,spec=capture(CURRENT,self.home,administrator_setup_result);self.assertEqual('image-captured',result['state'],result)
        rows=listing(CURRENT,self.home);self.assertEqual(([result['imageId']],0),([row['imageId']for row in rows['images']],rows['refusedImages']))
        now=rows['images'][0]['manifest']['createdAtUnixMs']+60_000
        self.assertEqual(result['imageId'],CURRENT.choose_image(rows,spec_dict(self.home/'vc-rw-select'),SETUP,now)['imageId'])
        self.assertIs(True,clone_start_admits(CURRENT,self.home,rows['images'][0],spec_dict(self.home/'vc-rw-select')))
        self.assertTrue(CURRENT.template_evidence_ok(template_logs(),SETUP))
        for name,change in (('system-principal',{'sysprepPrincipal':'S-1-5-18'}),('no-restart',{'restartScheduled':False})):
            with self.subTest(variant=name):
                changed=lambda module,operation,change=change:{**administrator_setup_result(module,operation),**change}
                self.assertEqual('instance_generalize_result',generalize(CURRENT,lambda operation:changed(CURRENT,operation))[0])
                refused,_=capture(CURRENT,self.home,changed)
                self.assertEqual(('refused','instance_capture_sysprep_context'),(refused['state'],refused.get('reason')))


@unittest.skipUnless(os.name=='posix','capture and listing check POSIX owners, modes and O_NOFOLLOW like their Linux host')
class FailedSchemaImageTests(unittest.TestCase):
    def test_f3_f3c_images_of_the_failed_schemas_are_never_listed_selected_or_cloned(self):
        """Images that F3 (schema 1), F3b (schema 2) and F3c (schema 3) templates produced."""
        for label,path in (('schema1',SCHEMA1),('schema2',SCHEMA2),('schema3',SCHEMA3)):
            with self.subTest(before=label),tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as folder:
                home=Path(folder);old=isolated(path);result,spec=capture(old,home,system_setup_result)
                self.assertEqual('image-captured',result['state'],result)
                rows=listing(old,home);now=rows['images'][0]['manifest']['createdAtUnixMs']+60_000
                # RED: the unfixed listing, selection and clone start reused the defective image.
                self.assertEqual([result['imageId']],[row['imageId']for row in rows['images']])
                self.assertEqual(result['imageId'],old.choose_image(rows,spec,SETUP,now)['imageId'])
                self.assertIs(True,clone_start_admits(old,home,rows['images'][0],spec))
                current=listing(CURRENT,home)
                # GREEN: the current listing, selection and clone start refuse it.
                self.assertEqual(([],1),([row['imageId']for row in current['images']],current['refusedImages']))
                self.assertIsNone(CURRENT.choose_image(rows,spec,SETUP,now))
                self.assertIn(clone_start_admits(CURRENT,home,rows['images'][0],spec),('refused:instance_image_directory','refused:instance_image_manifest'))


class IsolationTests(unittest.TestCase):
    def test_isolated_loader_is_neutral_and_beforeimages_are_authenticated(self):
        copy_of_current=loaded(Path(image.__file__).read_bytes(),'current_copy',image.__file__)
        self.assertEqual(clone_first_boot(image,image.image_answer_file(SETUP)),clone_first_boot(copy_of_current,copy_of_current.image_answer_file(SETUP)))
        record=json.loads(PROVENANCE.read_bytes())['files']
        for path in (SCHEMA1,SCHEMA2,SCHEMA3,SCHEMA4,SCHEMA5):
            self.assertEqual(record[path.name]['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(record[path.name]['imageSchemaVersion'],getattr(isolated(path),'IMAGE_SCHEMA_VERSION',1))


if __name__=='__main__':unittest.main()
