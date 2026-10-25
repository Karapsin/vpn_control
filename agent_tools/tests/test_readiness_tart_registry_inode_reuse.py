"""Whole-before RED/GREEN for the Tart disk pin replacement case under Linux inode numbering.

Fast Checks run 40187427911 (ubuntu-latest) failed the unfixed
test_disk_pin_allows_guest_writes_but_rejects_replacement in 2 ms. The case
unlinked disk.img and wrote a same-size replacement: Linux filesystems reissue
the freed inode number to the next inode created, so _disk_pin's (device,
inode, size, uid, mode) could not tell the files apart. APFS, the only Tart
host, never reissues a number. Here only the inode number _disk_pin observes
follows the Linux rule on every host; files, sizes and owners stay actual.
"""
import hashlib,itertools,json,os,sys,types,unittest,uuid
from pathlib import Path
from unittest import mock

from agent_tools import readiness_tart_registry as custody_module
from agent_tools.tests import test_readiness_tart_registry as current

FIXTURES=Path(__file__).parent/'fixtures/tart_disk_pin_inode_reuse'
BEFORE=FIXTURES/'test_readiness_tart_registry.py.before.source'
PROVENANCE=FIXTURES/'provenance.json'
BEFORE_SHA256='1a0d205ade728983121a9096b66e7144d6dafe13d8cb8403db381886db88a82b'
ORIGINAL='test_disk_pin_allows_guest_writes_but_rejects_replacement'


class LinuxInodeNumbers:
    """Lowest free number per new inode, as ext4 reissues a just-freed one.

    An earlier inode keeps its number while a name in the pinned file's directory
    or a descriptor of this process still holds it; afterwards it is free. A host
    filesystem that reissues the number itself (ext4 on the Linux runner) hands
    the replacement the freed inode's own key, which keeps that number, so the
    number every lstat observed (`observed`, in order) is the same on every host;
    `native` keeps the host's own inode numbers for diagnostics.
    """
    def __init__(self):
        self.numbers={};self.observed=[];self.native=[]

    @staticmethod
    def allocated(directory):
        live=set()
        for path in (directory,*directory.rglob('*')):
            try:info=os.lstat(path)
            except FileNotFoundError:continue
            live.add((info.st_dev,info.st_ino))
        for name in os.listdir('/dev/fd'):
            try:info=os.fstat(int(name))
            except OSError:continue
            live.add((info.st_dev,info.st_ino))
        return live

    def number(self,info,directory):
        key=(info.st_dev,info.st_ino)
        if key not in self.numbers:
            live=self.allocated(directory)
            taken={number for other,number in self.numbers.items() if other in live}
            self.numbers[key]=next(number for number in itertools.count(1)if number not in taken)
        self.observed.append(self.numbers[key]);self.native.append(info.st_ino)
        return self.numbers[key]


def numbered_path(numbers):
    """_disk_pin's Path, whose lstat reports the Linux-rule inode number."""
    class LinuxNumberedPath(type(Path())):
        def lstat(self):
            info=os.lstat(self)
            return types.SimpleNamespace(st_mode=info.st_mode,st_ino=numbers.number(info,Path(os.path.dirname(self))),
                                         st_dev=info.st_dev,st_nlink=info.st_nlink,st_uid=info.st_uid,st_gid=info.st_gid,st_size=info.st_size)
    return LinuxNumberedPath


@unittest.skipUnless(os.name=='posix','Tart custody uses POSIX owner locks')
class InodeReuseRegression(unittest.TestCase):
    def before(self):
        provenance=json.loads(PROVENANCE.read_bytes());raw=BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA256,len(raw),False),(provenance['sourceSha256'],provenance['sourceBytes'],provenance['nativeFailureClaimed']))
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(raw).hexdigest())
        self.assertEqual(current.__name__+'.TartCustodyTest.'+ORIGINAL,provenance['originalFailureTestId'])
        module=types.ModuleType('_tart_registry_before_'+uuid.uuid4().hex);module.__file__=current.__file__
        exec(compile(raw,str(BEFORE),'exec',dont_inherit=True),module.__dict__)
        return module

    @staticmethod
    def run_case(implementation):
        numbers=LinuxInodeNumbers()
        with mock.patch.object(custody_module,'Path',numbered_path(numbers)):
            case=implementation.TartCustodyTest(ORIGINAL);result=unittest.TestResult();case.run(result)
        return result,numbers

    def test_unfixed_red_and_fixed_green_under_linux_inode_numbers(self):
        old,old_numbers=self.run_case(self.before())
        new,new_numbers=self.run_case(current)
        details=lambda:'\n'.join(text for _,text in old.failures+old.errors+new.failures+new.errors)+'\nplatform=%s observed=%r/%r native=%r/%r'%(
            sys.platform,old_numbers.observed,new_numbers.observed,old_numbers.native,new_numbers.native)
        # Pins: the original, after the guest write, the replacement. Unfixed: the
        # unlinked original's number is reissued (by this rule, or by the host itself),
        # the replacement's pin repeats it and the original assertion fails exactly as
        # in run 40187427911.
        self.assertEqual((1,1,0,0),(old.testsRun,len(old.failures),len(old.errors),len(old.skipped)),details())
        self.assertEqual([1,1,1],old_numbers.observed,details())
        self.assertIn('self.assertNotEqual(custody_module._disk_pin(disk), before)',old.failures[0][1],details())
        # Fixed: the replacement is made while the original is still held, so it
        # gets a new number and the pin refuses it.
        self.assertEqual((1,0,0,0),(new.testsRun,len(new.failures),len(new.errors),len(new.skipped)),details())
        self.assertEqual([1,1,2],new_numbers.observed,details())

    def test_retained_whole_before_and_ci_evidence_custody(self):
        provenance=json.loads(PROVENANCE.read_bytes())
        self.assertFalse(provenance['nativeFailureClaimed'])
        self.assertEqual(BEFORE_SHA256,hashlib.sha256(BEFORE.read_bytes()).hexdigest())
        event=provenance['originalFailureEvent']
        self.assertEqual(('finished','failure',provenance['originalFailureTestId']),(event['event'],event['outcome'],event['publicTestId']))
        self.assertEqual(provenance['originalFailureEventSha256'],hashlib.sha256(json.dumps(event,sort_keys=True,separators=(',',':')).encode()).hexdigest())


if __name__=='__main__':unittest.main()
