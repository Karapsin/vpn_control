#!/usr/bin/env python3
import unittest
import struct
import xml.etree.ElementTree as ET
from windows_launcher_utf8 import ASM1, ASM3, UTF8_NS, utf8_manifest, require_unsigned_pe, verify_manifest


class ManifestTest(unittest.TestCase):
    def test_signed_and_truncated_pe_headers_are_rejected_for_both_formats(self):
        for magic, offset in ((0x10B, 152), (0x20B, 168)):
            pe = bytearray(176)
            pe[:4] = b"PE\0\0"
            struct.pack_into("<H", pe, 24, magic)
            require_unsigned_pe(pe)
            with self.assertRaises(ValueError):
                require_unsigned_pe(pe[:offset])
            struct.pack_into("<II", pe, offset, 4096, 1024)
            with self.assertRaises(ValueError):
                require_unsigned_pe(pe)

    def manifest(self, level="asInvoker"):
        return f'''<assembly xmlns="{ASM1}" manifestVersion="1.0" xmlns:asmv3="{ASM3}">
          <asmv3:trustInfo><asmv3:security><asmv3:requestedPrivileges>
          <asmv3:requestedExecutionLevel level="{level}" uiAccess="false"/>
          </asmv3:requestedPrivileges></asmv3:security></asmv3:trustInfo>
          <asmv3:application><asmv3:windowsSettings>
          <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
          </asmv3:windowsSettings></asmv3:application>
          <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="test"/></application></compatibility>
        </assembly>'''.encode()

    def test_utf8_is_idempotent_and_retains_security_dpi_and_compatibility(self):
        updated = utf8_manifest(self.manifest())
        verify_manifest(updated)
        self.assertEqual(updated, utf8_manifest(updated))
        root = ET.fromstring(updated)
        self.assertEqual("UTF-8", root.find(f".//{{{UTF8_NS}}}activeCodePage").text)
        self.assertEqual("asInvoker", root.find(f".//{{{ASM3}}}requestedExecutionLevel").get("level"))
        self.assertEqual("true", root.find(".//{http://schemas.microsoft.com/SMI/2005/WindowsSettings}dpiAware").text)
        self.assertEqual("test", root.find(".//{urn:schemas-microsoft-com:compatibility.v1}supportedOS").get("Id"))

    def test_read_only_verification_rejects_missing_or_wrong_code_page(self):
        for content in (self.manifest(), utf8_manifest(self.manifest()).replace(b">UTF-8<", b">Legacy<")):
            with self.subTest(content=content), self.assertRaises(ValueError):
                verify_manifest(content)

    def test_refuses_elevation_and_ambiguous_or_unsafe_manifests(self):
        for content in (self.manifest("requireAdministrator"), b"<assembly/>",
                        b'<!DOCTYPE assembly><assembly/>', self.manifest().replace(b"</asmv3:application>", b"</asmv3:application><asmv3:application/>")):
            with self.subTest(content=content), self.assertRaises(ValueError):
                utf8_manifest(content)


if __name__ == "__main__":
    unittest.main()
