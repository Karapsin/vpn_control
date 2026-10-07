"""Portable causal template checks; no subprocess, private program, or native IO.

Exact original/repaired guard snapshots operate on nonsecret source examples.
The baseline must already be source-authenticated by the operational caller;
these tests prove template comparison, not source admission or native success.
"""
import unittest
from agent_tools.tests.fixtures import android_owner_key_template_equivalence as fixture

CURRENT='10000000-0000-4000-8000-000000000001'
REVIEWED='20000000-0000-4000-8000-000000000001'
KEYS=('host','device','correlationId','sourceSha','expectedAvd','expectedApi','packageSha256','reservation')


def program(keys=KEYS,correlation=REVIEWED,line_tail=''):
    return ('import json\nOWNER_ADMISSION_KEYS={'+','.join(repr(k)for k in keys)+'}'+line_tail+'\nREQUEST_ID='+repr(correlation)+'\nRESULT=False\n').encode()


class OwnerKeyEquivalenceTests(unittest.TestCase):
    def test_actual_guard_accepts_only_exact_key_permutation_and_approved_uuid(self):
        guard=fixture.original_guard();old=program();new=program(tuple(reversed(KEYS)),CURRENT)
        self.assertNotEqual(old,new.replace(CURRENT.encode(),REVIEWED.encode()))
        self.assertTrue(guard(new,old,CURRENT,REVIEWED))
    def test_source_authenticated_original_guard_exposes_same_line_code_gap(self):
        guard=fixture.original_guard();changed=program(tuple(reversed(KEYS)),CURRENT,'; FOREIGN_CODE=1')
        # Preserve the causal pre-fix acceptance without pretending it is safe.
        self.assertTrue(guard(changed,program(),CURRENT,REVIEWED))
    def test_original_guard_refuses_other_schema_and_line_changes(self):
        guard=fixture.original_guard();old=program()
        for changed in (program(KEYS+('extra',),CURRENT),program(KEYS[:-1],CURRENT),program(KEYS[:-1]+(123,),CURRENT),program(KEYS[:-1]+(KEYS[0],),CURRENT),program(tuple(reversed(KEYS)),CURRENT)+b'EXTRA=1\n',program(correlation='30000000-0000-4000-8000-000000000001'),program(correlation=CURRENT)+b'OWNER_ADMISSION_KEYS={"host"}\n'):
            with self.subTest(changed=changed):self.assertFalse(guard(changed,old,CURRENT,REVIEWED))

    def test_fixed_guard_preserves_exact_permutation_and_uuid_equivalence(self):
        guard=fixture.fixed_guard();baseline=program()
        for keys in (KEYS,tuple(reversed(KEYS)),KEYS[3:]+KEYS[:3]):
            with self.subTest(keys=keys):self.assertTrue(guard(program(keys,CURRENT),baseline,CURRENT,REVIEWED))
        self.assertFalse(baseline==program(tuple(reversed(KEYS)),CURRENT).replace(CURRENT.encode(),REVIEWED.encode()))
    def test_fixed_guard_refuses_same_line_code_and_comment_changes(self):
        guard=fixture.fixed_guard()
        for tail in ('; FOREIGN_CODE=1','; print("foreign")',' # foreign comment'):
            with self.subTest(tail=tail):self.assertFalse(guard(program(tuple(reversed(KEYS)),CURRENT,tail),program(),CURRENT,REVIEWED))
    def test_fixed_guard_refuses_schema_multiple_assignment_and_other_code_changes(self):
        guard=fixture.fixed_guard();baseline=program()
        for changed in (program(KEYS+('extra',),CURRENT),program(KEYS[:-1],CURRENT),program(KEYS[:-1]+(123,),CURRENT),program(KEYS[:-1]+(KEYS[0],),CURRENT),program(tuple(reversed(KEYS)),CURRENT)+b'EXTRA=1\n',program(correlation='30000000-0000-4000-8000-000000000001'),program(correlation=CURRENT)+b'OWNER_ADMISSION_KEYS={"host"}\n',program(correlation=CURRENT).replace(b'OWNER_ADMISSION_KEYS=',b'OWNER_ADMISSION_KEYS=FOREIGN='),program(correlation=CURRENT).replace(b'RESULT=False',b'RESULT=True'),program(correlation=CURRENT).replace(b'OWNER_ADMISSION_KEYS=',b' OWNER_ADMISSION_KEYS=')):
            with self.subTest(changed=changed):
                try:accepted=guard(changed,baseline,CURRENT,REVIEWED)
                except (SyntaxError,IndentationError):accepted=False
                self.assertFalse(accepted)

if __name__=='__main__':unittest.main()
