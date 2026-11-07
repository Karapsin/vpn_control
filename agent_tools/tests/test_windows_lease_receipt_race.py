"""A lease receipt reader never sees a half-written or locked file.

The owner publishes while cancellation and status read. Run natively on clone
246a3304, where the exact Write of the whole preserved source lost reads (the cause of
the UNKNOWN cancel of ce43c202) and the current one lost none. The native class also
runs in the Windows package job; its first hosted run comes with the first push.
"""
import ast,hashlib,json,os,re,shutil,subprocess,tempfile,unittest
from pathlib import Path
from agent_tools import readiness_windows_leases as leases

FIXTURE=Path(__file__).parent/'fixtures/windows_native_tools_20261106'
WRITE=re.compile(r'static void Write\(string path,Dictionary<string,object> value\)\{.*?\}\}?\n',re.S)


def write_method(source):
    found=[match.group(0) for match in re.finditer(r'^ static void Write\(string path,Dictionary<string,object> value\)\{.*$',source,re.M)]
    if len(found)!=1:raise AssertionError('lease Write is not unique')
    return found[0]


def before_source():
    raw=(FIXTURE/'leases.before.source').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sha256']['leases.before.source']:raise AssertionError('leases beforeimage changed')
    return raw.decode()


def read_method(source):
    found=[match.group(0) for match in re.finditer(r'^ static Dictionary<string,object> Read\(string path\)\{.*$',source,re.M)]
    if len(found)!=1:raise AssertionError('lease Read is not unique')
    return found[0]


def race_script(source,*,rounds=400):
    """Run the exact Read and Write of one source; count what a concurrent reader loses."""
    helpers=(" static void Need(bool yes,string reason){if(!yes)throw new Exception(reason);}\n"
             " static void NoLink(string path){Need((File.GetAttributes(path)&FileAttributes.ReparsePoint)==0,\"REPARSE_POINT\");}\n")
    native=("using System;using System.IO;using System.Text;using System.Threading;using System.Collections.Generic;using System.Web.Script.Serialization;\n"
            "public static class ReceiptRace {\n static readonly JavaScriptSerializer Json=new JavaScriptSerializer();\n"+helpers+read_method(source)+"\n"+write_method(source)+"\n"
            " public static string Run(string root,int rounds){\n  int lost=0,seen=0,sharing=0,parse=0,other=0;long stop=0;string current=null;\n"
            "  var reader=new Thread(()=>{while(Interlocked.Read(ref stop)==0){string path=Volatile.Read(ref current);if(path==null||!File.Exists(path))continue;\n"
            "    try{var v=Read(path);if(v==null||!v.ContainsKey(\"state\")){Interlocked.Increment(ref lost);Interlocked.Increment(ref parse);}else Interlocked.Increment(ref seen);}\n"
            "    catch(FileNotFoundException){}catch(IOException){Interlocked.Increment(ref lost);Interlocked.Increment(ref sharing);}catch(Exception){Interlocked.Increment(ref lost);Interlocked.Increment(ref other);}}});\n"
            "  reader.Start();\n  for(int i=0;i<rounds;i++){string path=Path.Combine(root,\"terminal-\"+i+\".json\");Volatile.Write(ref current,path);Thread.Sleep(1);\n"
            "   Write(path,new Dictionary<string,object>{{\"state\",\"cancelled\"},{\"padding\",new string('x',8192)}});Thread.Sleep(1);}\n"
            "  Interlocked.Exchange(ref stop,1);reader.Join();return lost+\":\"+seen+\":\"+sharing+\":\"+parse+\":\"+other;\n }\n}\n")
    return ("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n"
            "Add-Type -ReferencedAssemblies System.Web.Extensions -TypeDefinition @'\n"+native+"'@\n"
            "$root=Join-Path $env:TEMP ('vc-receipt-race-'+[Guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null\n"
            "try{$counts=[ReceiptRace]::Run($root,"+str(rounds)+").Split(':')}finally{Remove-Item -LiteralPath $root -Recurse -Force}\n"
            "[Console]::WriteLine((@{lost=[int]$counts[0];seen=[int]$counts[1];sharing=[int]$counts[2];parse=[int]$counts[3];other=[int]$counts[4]}|ConvertTo-Json -Compress))\n")


class SourceTests(unittest.TestCase):
    def test_before_write_publishes_in_place_current_moves_a_finished_file(self):
        old=write_method(before_source());new=write_method(Path(leases.__file__).read_text())
        self.assertIn('new FileStream(path,FileMode.CreateNew',old);self.assertNotIn('File.Move',old)
        self.assertIn('new FileStream(temp,FileMode.CreateNew',new);self.assertLess(new.index('f.Flush(true)'),new.index('File.Move(temp,path)'))

    def test_before_read_has_one_try_current_retries_only_transient_sharing_within_a_bound(self):
        self.assertNotIn('catch(IOException)',read_method(before_source()))
        new=read_method(Path(leases.__file__).read_text())
        self.assertIn('catch(IOException){if(attempt>=40||!File.Exists(path))throw;Thread.Sleep(25);}',new)


@unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'Actual Windows file sharing race')
class NativeRaceTests(unittest.TestCase):
    def counts(self,source):
        with tempfile.TemporaryDirectory()as directory:
            path=Path(directory)/'race.ps1';path.write_text(race_script(source),encoding='utf-8')
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,timeout=120)
        self.assertEqual(0,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))
        return json.loads(result.stdout.decode('utf-8-sig'))
    def test_before_loses_reads_current_loses_none(self):
        self.assertGreater(self.counts(before_source())['lost'],0)
        self.assertEqual(0,self.counts(Path(leases.__file__).read_text())['lost'])


if __name__=='__main__':unittest.main()
