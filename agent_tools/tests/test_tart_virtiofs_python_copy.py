"""Source-authenticated complete copy calls, real files, metadata-only fault.

No privileged bootstrap, guest command, authentication, VM or transport runs.
The original and new whole installers remain evidence; only their exact copy
invocation is admitted into an owned temporary prefix.
"""
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/tart_virtiofs_python_copy'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def copy_block(raw, expected_sha, flags):
    if sha(raw) != expected_sha:
        raise ValueError('copy_installer_source_changed')
    expected = '/bin/cp ' + flags + ' "$SHARE/python/python" "$PREFIX/python"'
    copies = [line for line in raw.decode('utf-8').splitlines() if '/bin/cp' in line]
    if copies != [expected] or flags not in ('-RP', '-RPX'):
        raise ValueError('copy_invocation_shape_changed')
    return expected


def tree(root):
    root = Path(root)
    result = {}
    for directory, directories, files in os.walk(root, followlinks=False):
        for path in [Path(directory), *(Path(directory)/name for name in sorted(directories + files))]:
            info = path.lstat()
            row = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid}
            if stat.S_ISLNK(info.st_mode):
                row.update(kind='symlink', target=os.readlink(path))
            elif stat.S_ISREG(info.st_mode):
                row.update(kind='file', size=info.st_size, sha256=sha(path.read_bytes()))
            elif stat.S_ISDIR(info.st_mode):
                row.update(kind='directory')
            else:
                raise AssertionError('unsupported temporary public payload object')
            result[str(path.relative_to(root))] = row
    return result


# The real cp performs all data, link and mode work. This external ABI seam
# supplies the one VirtioFS metadata failure documented by Apple's copy_link:
# !Xflag attempts COPYFILE_XATTR|COPYFILE_NOFOLLOW after symlink creation.
# GNU cp has no Apple -X; its ordinary -RP does not preserve xattrs by default.
# That metadata-only flag translation leaves the actual data/link flags intact.
CP_METADATA_PEER = r'''
import errno,json,os,pathlib,subprocess,sys
flags,source,destination=sys.argv[1:]
if flags not in ('-RP','-RPX'):raise SystemExit(64)
actual_flags=flags if sys.platform=='darwin' else '-RP'
result=subprocess.run(['/bin/cp',actual_flags,source,destination],check=False)
links=sorted(str(p.relative_to(source))for p in pathlib.Path(source).rglob('*')if p.is_symlink())
record={'flags':flags,'dataExitCode':result.returncode,'symlinks':links,'metadataAttempted':flags=='-RP'}
with open(os.environ['COPY_METADATA_EVENTS'],'a')as output:output.write(json.dumps(record,sort_keys=True)+'\n')
if result.returncode:raise SystemExit(result.returncode)
if flags=='-RP' and links:
 sys.stderr.write('cp: could not copy symlink extended attributes: '+os.strerror(errno.ELOOP)+'\n')
 raise SystemExit(1)
raise SystemExit(0)
'''


@unittest.skipUnless(os.name == 'posix' and Path('/bin/cp').is_file(), 'real POSIX copy tool')
class VirtiofsPythonCopyTests(unittest.TestCase):
    def setUp(self):
        # The bootstrap copies run under the default account umask; model it.
        self.addCleanup(os.umask, os.umask(0o022))
        self.temporary = tempfile.TemporaryDirectory(prefix='tart-copy-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.share = self.root / 'public-share'
        self.source = self.share / 'python/python'
        (self.source/'bin').mkdir(parents=True)
        (self.source/'lib').mkdir()
        for directory in (self.source, self.source/'bin', self.source/'lib'):
            directory.chmod(0o755)
        executable = self.source/'bin/python3.12'
        executable.write_bytes(b'#!/bin/sh\nexit 99 # public synthetic copy payload, never executed\n')
        executable.chmod(0o755)
        library = self.source/'lib/public.py'
        library.write_bytes(b'PUBLIC_COPY_SENTINEL = 1\n'); library.chmod(0o644)
        (self.source/'bin/python3').symlink_to('python3.12')
        self.events = self.root/'metadata-events.jsonl'
        self.peer = self.root/'cp-metadata-peer'
        self.peer.write_text('#!'+sys.executable+'\n'+CP_METADATA_PEER)
        self.peer.chmod(0o700)
        self.provenance = json.loads((FIXTURE/'provenance.json').read_bytes())

    def caller(self, name, prefix):
        flags = '-RP' if name == 'bootstrap.before.sh' else '-RPX'
        raw = (FIXTURE/name).read_bytes()
        block = copy_block(raw, self.provenance['sourceSha256'][name], flags)
        # Exact copy statement; replace only its executable with the documented
        # metadata peer. Every operand and native flag stays source-derived.
        block = shlex.quote(str(self.peer)) + block.removeprefix('/bin/cp')
        program = ('set -eu\numask 022\nSHARE='+shlex.quote(str(self.share))+
                   '\nPREFIX='+shlex.quote(str(prefix))+
                   '\n[ ! -e "$PREFIX" ] && [ ! -L "$PREFIX" ] || exit 73\n'
                   '/bin/mkdir -m 755 "$PREFIX"\n'
                   'printf "%s\\n" started > "$PREFIX/copy-started"\n'+block+
                   '\nprintf "%s\\n" complete > "$PREFIX/copy-complete"\n')
        environment = dict(os.environ, COPY_METADATA_EVENTS=str(self.events))
        return subprocess.run(['/bin/sh','-c',program], env=environment,
                              capture_output=True, timeout=5, check=False)

    def test_complete_old_copy_red_new_copy_green_preserves_original_partial_prefix(self):
        original = self.root/'original-prefix'
        before = self.caller('bootstrap.before.sh', original)
        self.assertEqual(1, before.returncode)
        self.assertIn(b'could not copy symlink extended attributes', before.stderr)
        self.assertIn(b'Too many levels', before.stderr)
        self.assertTrue((original/'copy-started').is_file())
        self.assertFalse((original/'copy-complete').exists())
        expected = tree(self.source)
        self.assertEqual(expected, tree(original/'python'))
        partial = tree(original)
        fixed = self.root/'new-continuation-prefix'
        after = self.caller('bootstrap-continuation.sh', fixed)
        self.assertEqual(0, after.returncode, after.stderr.decode())
        self.assertEqual(b'', after.stderr)
        self.assertEqual(expected, tree(fixed/'python'))
        self.assertEqual(partial, tree(original))
        self.assertEqual(b'complete\n', (fixed/'copy-complete').read_bytes())
        for prefix in (original, fixed):
            link = prefix/'python/bin/python3'
            self.assertTrue(stat.S_ISLNK(link.lstat().st_mode))
            self.assertEqual('python3.12', os.readlink(link))
            self.assertEqual(stat.S_IMODE((self.source/'bin/python3').lstat().st_mode),
                             stat.S_IMODE(link.lstat().st_mode))
        records = [json.loads(line) for line in self.events.read_text().splitlines()]
        self.assertEqual(['-RP','-RPX'], [row['flags'] for row in records])
        self.assertEqual([0,0], [row['dataExitCode'] for row in records])
        self.assertEqual([True,False], [row['metadataAttempted'] for row in records])
        self.assertEqual([['bin/python3']]*2, [row['symlinks'] for row in records])
        # A consumed or partial prefix is never submitted again or overwritten.
        for name, prefix in [('bootstrap.before.sh',original),('bootstrap-continuation.sh',fixed)]:
            self.assertEqual(73, self.caller(name, prefix).returncode)
        self.assertEqual(2, len(self.events.read_text().splitlines()))
        self.assertEqual(partial, tree(original))

    def test_symbolic_link_prefix_never_receives_a_copy(self):
        outside = self.root/'outside'; outside.mkdir()
        prefix = self.root/'existing-prefix'; prefix.symlink_to(outside, target_is_directory=True)
        self.assertEqual(73, self.caller('bootstrap-continuation.sh', prefix).returncode)
        self.assertEqual([], list(outside.iterdir()))
        self.assertFalse(self.events.exists())

    def test_whole_source_and_exact_copy_shape_are_both_required(self):
        raw = (FIXTURE/'bootstrap-continuation.sh').read_bytes()
        expected = self.provenance['sourceSha256']['bootstrap-continuation.sh']
        with self.assertRaisesRegex(ValueError, 'copy_installer_source_changed'):
            copy_block(raw+b'\n', expected, '-RPX')
        for mutation in (raw.replace(b'-RPX',b'-RLX'),
                         raw.replace(b'"$PREFIX/python"\n',b'"$PREFIX/python"; /bin/echo extra\n'),
                         raw+b'/bin/cp -RPX another destination\n'):
            with self.assertRaisesRegex(ValueError, 'copy_invocation_shape_changed'):
                copy_block(mutation, sha(mutation), '-RPX')

    def test_public_native_evidence_is_bound_to_complete_sources_and_manifest(self):
        for name, expected in self.provenance['sourceSha256'].items():
            self.assertEqual(expected, sha((FIXTURE/name).read_bytes()))
        raw = (FIXTURE/'native-public-evidence.json').read_bytes()
        self.assertEqual(self.provenance['nativePublicEvidenceSha256'], sha(raw))
        evidence = json.loads(raw)
        self.assertEqual(evidence['originalInstallerSha256'], self.provenance['sourceSha256']['bootstrap.before.sh'])
        self.assertEqual(evidence['fixedContinuationSha256'], self.provenance['sourceSha256']['bootstrap-continuation.sh'])
        manifest = json.loads((FIXTURE/'public-share-manifest.before.json').read_bytes())
        self.assertEqual(evidence['publicManifestRows'], len(manifest['pins']))
        rows = {row['path']:row for row in manifest['pins']}
        self.assertEqual(len(manifest['pins']), len(rows))
        symlink = rows[evidence['nativeHarmlessProbe']['sourceRelativePath']]
        self.assertEqual('symlink', symlink['kind'])
        self.assertEqual(evidence['nativeHarmlessProbe']['bothLinkTarget'], symlink['target'])
        self.assertEqual(evidence['nativeHarmlessProbe']['bothDisplayedModeOctal'],
                         format(stat.S_IMODE(symlink['generation'][2]),'04o'))
        self.assertEqual(1,evidence['nativeHarmlessProbe']['oldExitCode'])
        self.assertEqual(0,evidence['nativeHarmlessProbe']['newExitCode'])
        self.assertFalse(evidence['originalPartialPrefix']['automaticReplay'])
        self.assertNotEqual(evidence['originalPartialPrefix']['path'], evidence['newContinuationPrefix'])


if __name__ == '__main__':
    unittest.main()
