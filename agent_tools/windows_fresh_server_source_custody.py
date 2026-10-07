"""Enroll authenticated sibling sources in the existing public source guard.

No construction of native/private authority, dispatch, or source re-adoption.
"""
import os
from pathlib import Path

def expand_public_inputs(inputs,held):
 """Enroll exactly already-authenticated held sources into the existing guard.
 Duplicate descriptors preserve custody; all overlapping source/parent pins must
 agree before any enrollment. No mutable named body is reopened or adopted.
 """
 held.finish();inputs.verify()
 for name,(fd,pin,digest,raw)in held.files.items():
  if inputs.root not in Path(name).parents:raise ValueError('sibling-expanded-source-root')
  expected={'generation':list(pin),'sha256':digest}
  if name in inputs.pins and inputs.pins[name]!=expected:raise ValueError('sibling-expanded-source-conflict')
  if name in inputs.bytes and inputs.bytes[name]!=raw:raise ValueError('sibling-expanded-body-conflict')
 for name,(fd,pin)in held.parents.items():
  if name in inputs.parents and list(inputs.parents[name][1])!=list(pin):raise ValueError('sibling-expanded-parent-conflict')
 for name,(fd,pin,digest,raw)in held.files.items():
  if name not in inputs.fds:
   inputs.fds[name]=os.dup(fd);inputs.pins[name]={'generation':list(pin),'sha256':digest};inputs.bytes[name]=raw
 for name,(fd,pin)in held.parents.items():
  if name not in inputs.parents:inputs.parents[name]=(os.dup(fd),list(pin))
 inputs.verify();held.finish()
