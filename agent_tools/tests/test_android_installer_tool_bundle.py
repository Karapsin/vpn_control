"""Fixed reviewed installer tools are separate from product source admission."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import android_installer_tool_bundle as bundle


class InstallerToolBundleTest(unittest.TestCase):
    def source(self, root):
        for name in bundle.FILES:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('tool:'+name).encode())
        return bundle.reviewed_tree(root)['treeSha256']

    def prepared(self, root):
        digest=self.source(root);prepared=bundle.prepare(root,digest)
        loaded=bundle.load(root,prepared['toolBundleId'])
        registry=root/'.rag_index/android-installer-tool-bundles'
        anchor=registry/(prepared['toolBundleId']+'.json')
        binding=json.loads(anchor.read_bytes());folder=registry/binding['directory']
        return prepared,loaded,anchor,folder

    def test_exact_reviewed_frozen_files_load_independently_of_later_checkout(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);prepared,loaded,anchor,folder=self.prepared(root)
            self.assertEqual(set(bundle.FILES),set(loaded['files']))
            (root/bundle.FILES[0]).write_bytes(b'new unreviewed checkout')
            self.assertEqual(loaded,bundle.load(root,prepared['toolBundleId']))
            self.assertNotIn('sourceSha',loaded)

    def test_explicit_unapproved_digest_rejects_before_registry_or_snapshot(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);self.source(root)
            for digest in (None,'bad','0'*64):
                with self.assertRaises(ValueError):bundle.prepare(root,digest)
            self.assertFalse((root/'.rag_index').exists())

    def test_source_symlink_hardlink_and_ancestry_rejected(self):
        for attack in ('symlink','hardlink','ancestor'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw);digest=self.source(root);path=root/bundle.FILES[0]
                if attack=='hardlink':os.link(path,root/'alias')
                elif attack=='symlink':path.rename(root/'alias');path.symlink_to(root/'alias')
                else:(root/'agent_tools').rename(root/'foreign');(root/'agent_tools').symlink_to(root/'foreign',target_is_directory=True)
                with self.assertRaises(ValueError):bundle.prepare(root,digest)
                self.assertFalse((root/'.rag_index').exists())

    def test_snapshot_inventory_generations_and_private_files_cannot_change(self):
        for attack in ('rewrite','replace','mode','hardlink','symlink','manifest-rewrite','anchor-rewrite','extra-file','extra-dir','ancestor'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as raw:
                root=Path(raw);prepared,loaded,anchor,folder=self.prepared(root);path=folder/bundle.FILES[0]
                if attack=='rewrite':path.write_bytes(path.read_bytes())
                elif attack=='replace':data=path.read_bytes();path.unlink();path.write_bytes(data);path.chmod(0o600)
                elif attack=='mode':path.chmod(0o644)
                elif attack=='hardlink':os.link(path,root/'alias')
                elif attack=='symlink':path.rename(root/'alias');path.symlink_to(root/'alias')
                elif attack=='manifest-rewrite':p=folder/'manifest.json';p.write_bytes(p.read_bytes())
                elif attack=='anchor-rewrite':anchor.write_bytes(anchor.read_bytes())
                elif attack=='extra-file':(folder/'scripts/foreign.py').write_bytes(b'foreign')
                elif attack=='extra-dir':(folder/'empty').mkdir(mode=0o700)
                else:(folder/'agent_tools').rename(folder/'other');(folder/'agent_tools').symlink_to(folder/'other',target_is_directory=True)
                with self.assertRaises(ValueError):bundle.load(root,prepared['toolBundleId'])

    def test_same_byte_source_rewrite_during_prepare_rejects_publication(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);digest=self.source(root);original=bundle._write;changed=False
            def rewrite(path,data):
                nonlocal changed
                original(path,data)
                if not changed:
                    source=root/bundle.FILES[0];source.write_bytes(source.read_bytes());changed=True
            with mock.patch.object(bundle,'_write',side_effect=rewrite):
                with self.assertRaises(ValueError):bundle.prepare(root,digest)
            self.assertEqual([],list((root/'.rag_index/android-installer-tool-bundles').glob('sha256-*.json')))

    def test_snapshot_rewrite_during_load_rejects_before_returning_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);prepared,loaded,anchor,folder=self.prepared(root);original=bundle._read;changed=False
            def rewrite(path,**kwargs):
                nonlocal changed
                result=original(path,**kwargs)
                if path==folder/bundle.FILES[0] and not changed:
                    path.write_bytes(path.read_bytes());changed=True
                return result
            with mock.patch.object(bundle,'_read',side_effect=rewrite):
                # Pin comparison must also recheck every opened path after reads.
                with self.assertRaises(ValueError):bundle.load(root,prepared['toolBundleId'])
