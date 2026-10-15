"""Narrow installed-package/runtime policy reconciliation for Arch swtpm.

This accepts only one UID mismatch, on the mutable CA directory, when its
metadata exactly matches the package's independently checked tmpfiles policy.
No other pacman warning or file alteration is ignored. This function supplies
no native authority; its caller must observe and hold every argument itself.
"""
from __future__ import annotations


def swtpm_runtime_owner_accepted(return_code,stdout,stderr,policy,metadata,uid,gid):
    import re,stat
    if type(return_code)is not int or return_code!=1:return False
    if type(stdout)is not bytes or type(stderr)is not bytes:return False
    if re.fullmatch(rb'swtpm: [1-9][0-9]{0,5} total files, 1 altered file\n',stdout)is None:return False
    if stderr!=b'warning: swtpm: /var/lib/swtpm-localca (UID mismatch)\n':return False
    if type(policy)is not str or len(policy.encode())>16384:return False
    rows=[line.split() for line in policy.splitlines() if line.strip() and not line.lstrip().startswith('#')]
    if len(rows)!=1:return False
    row=rows[0]
    if len(row) not in (5,6) or row[:3]!=['z','/var/lib/swtpm-localca','0750'] or len(row)==6 and row[5]!='-':return False
    if any(re.fullmatch('[a-z_][a-z0-9_-]{0,63}',name)is None for name in row[3:5]):return False
    if any(type(x)is not int or not 0<=x<2**32 for x in (uid,gid)):return False
    if type(metadata)is not dict or set(metadata)!={'mode','uid','gid'}:return False
    return (all(type(x)is int for x in metadata.values()) and stat.S_ISDIR(metadata['mode'])
            and stat.S_IMODE(metadata['mode'])==0o750 and metadata['uid']==uid and metadata['gid']==gid)
