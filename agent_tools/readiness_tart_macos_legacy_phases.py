"""Finite original-only closure of qualified historical Mac input phases.

All retained programs are DATA and are never executed. Exact source/receipt
pins plus source-known before-input absences establish input-phase completion,
not historical semantic success, controller process termination or power-idle
visibility. Ordinary credentials, secret journals and images are never read.
"""
from __future__ import annotations
from contextlib import ExitStack
from copy import deepcopy
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import CodeType
from . import private_inventory_lock as private
from . import readiness_tart_macos_registry as registry
from . import readiness_tart_macos_legacy_gui as inventory
from . import readiness_tart_macos_legacy_public_resolution as public
from . import readiness_tart_macos_unlock_qualification as qualification
from . import readiness_tart_vnc as rfb
_EXECUTING_CODE=sys._getframe().f_code
_TOKEN=object()
_ORIGINAL_RUN='2d933a39-0fb6-46a4-9fd9-02221d81c4b9'
_SCAFFOLD_NAME='legacy-gui-metadata-inventory-8dad25f7-b8b3-452b-811e-8b8ed964db7f.json'
_SCAFFOLD_SHA='3801715a5449f43fe494c6a954b33b849ddf991685f58827062a9713d1d845bd'
_CASES={'native-held-source-wake-73cac3f1-4bde-4e7f-bb13-9f0067bdff9d': {'absent': [],
                                                                  'entries': ['intent.json',
                                                                              'producer.py',
                                                                              'result.json'],
                                                                  'files': {'intent.json': 'b1438e5703015d1d5e8ea68c1d51fba893077d61a420b0a1292e66e54384fb8b',
                                                                            'producer.py': '823d178772a8ab449874671e8c76a7e80ffe6943bab827de601af4daf4ce59ad',
                                                                            'result.json': 'a3407d0a1cdcd461157a6b875e41124fcc6b99c7b325ac06a127578b145c7c5a'},
                                                                  'kind': 'finished',
                                                                  'nested': {},
                                                                  'phaseFacts': [],
                                                                  'publicOriginal': None,
                                                                  'rootFiles': {'macos-wake-73cac3f1-4bde-4e7f-bb13-9f0067bdff9d-observed.json': '6cdb8575438253971e83eb62639a25b9daff2f1230fe2928a6368dd145d6f7da',
                                                                                'macos-wake-73cac3f1-4bde-4e7f-bb13-9f0067bdff9d-transport.json': 'c3b8d3ac200582ee11fa958d79280d1abaa7d8b14b284071f30072b71a9a844a',
                                                                                'macos-wake-73cac3f1-4bde-4e7f-bb13-9f0067bdff9d.json': '7cdd087830e25b4cff63474a4fe9684370c42e89647bf559d293c815898bd3d5'}},
 'native-public-MacMeta-SuperL-selectall-failure-1792511225927702000': {'absent': [],
                                                                        'entries': ['macos-provision-ui-helper.py',
                                                                                    'original-failure.json',
                                                                                    'readiness_tart_vnc.py'],
                                                                        'files': {'macos-provision-ui-helper.py': 'd38c7b9a5354de3e512bd11483659651df5d8720897dbbcd8e0cf84d3eace584',
                                                                                  'original-failure.json': '69b271a7af2ac7487eb299abde7c6536ae71873a78e4df56d810bd527f4178e5',
                                                                                  'readiness_tart_vnc.py': '8dbd9f8256232a449c8628e63cf09c2d0949f62935ee29cc91b1c8759dc0cd2c'},
                                                                        'kind': 'archive',
                                                                        'nested': {},
                                                                        'phaseFacts': [],
                                                                        'publicOriginal': 'e25cbf63-05c8-439a-b5be-287a0bf81fa3',
                                                                        'rootFiles': {}},
 'native-public-MacMeta-selectall-failure-1792510986253610000': {'absent': [],
                                                                 'entries': ['macos-provision-ui-helper.py',
                                                                             'original-failure.json',
                                                                             'readiness_tart_vnc.py'],
                                                                 'files': {'macos-provision-ui-helper.py': 'd38c7b9a5354de3e512bd11483659651df5d8720897dbbcd8e0cf84d3eace584',
                                                                           'original-failure.json': '6271ce9224042d5f4ad5accdc02c551fc064101047998ace28abf71686ad1ddf',
                                                                           'readiness_tart_vnc.py': '4b83be6b11f98c496c1ebad1c947883d3062160d039a11e3f3cc536df49911b1'},
                                                                 'kind': 'archive',
                                                                 'nested': {},
                                                                 'phaseFacts': [],
                                                                 'publicOriginal': 'c55469cc-1cb6-46d2-8793-e1e6ca95a799',
                                                                 'rootFiles': {}},
 'native-public-existing-Alt-diagnostic-1792511303827478000': {'absent': [],
                                                               'entries': ['diagnostic-plan.json',
                                                                           'macos-provision-ui-helper.py',
                                                                           'native-observation.json',
                                                                           'readiness_tart_vnc.py'],
                                                               'files': {'diagnostic-plan.json': 'a7a8e926a687a47a237b667eec544d9638918e61206327b9dbe782903af9edca',
                                                                         'macos-provision-ui-helper.py': 'd38c7b9a5354de3e512bd11483659651df5d8720897dbbcd8e0cf84d3eace584',
                                                                         'native-observation.json': '5f51d21f2a00a5106c7cfbc61351751f981391ab6dd10230260ff0e017eb76c0',
                                                                         'readiness_tart_vnc.py': '8dbd9f8256232a449c8628e63cf09c2d0949f62935ee29cc91b1c8759dc0cd2c'},
                                                               'kind': 'archive',
                                                               'nested': {},
                                                               'phaseFacts': [],
                                                               'publicOriginal': '1cc8e0d8-ec05-4987-8de6-9ca9f108f98b',
                                                               'rootFiles': {}},
 'native-public-uppercase-failure-1792508717084346000': {'absent': [],
                                                         'entries': ['macos-provision-ui-helper.py',
                                                                     'original-failure.json',
                                                                     'readiness_tart_vnc.py'],
                                                         'files': {'macos-provision-ui-helper.py': 'd38c7b9a5354de3e512bd11483659651df5d8720897dbbcd8e0cf84d3eace584',
                                                                   'original-failure.json': 'a89601afb14b1c227ea68e04d300a4714ef6159e2b166b984ef0d4f44d97040b',
                                                                   'readiness_tart_vnc.py': '0a6fee82aee519f5f1fca489a14e705e7b168a31fec3d6393498e629c959bc49'},
                                                         'kind': 'archive',
                                                         'nested': {},
                                                         'phaseFacts': [],
                                                         'publicOriginal': '99dbd019-27b7-4c75-bbea-fbb59c5438ca',
                                                         'rootFiles': {}},
 'native-state-bound-wake-7f436366-69b7-4ddc-87b4-efb95478441a': {'absent': [],
                                                                  'entries': ['intent.json',
                                                                              'qualified-wake-source.py',
                                                                              'result.json'],
                                                                  'files': {'intent.json': '9d37b53359da1bcdf7b46d407e25ab90d01bf9e718c79bd02bfb91b8fc269745',
                                                                            'qualified-wake-source.py': '4864dec7d3f513ce1d7eb8ceb69c4cf08cdb2d7660dd9d96e985c97f924a4f5c',
                                                                            'result.json': 'bc704c464bbb25e5dd856fc4cbe99ca477f0470e0be3ad2656a81d217804cc42'},
                                                                  'kind': 'finished',
                                                                  'nested': {},
                                                                  'phaseFacts': [],
                                                                  'publicOriginal': None,
                                                                  'rootFiles': {'macos-wake-7f436366-69b7-4ddc-87b4-efb95478441a-observed.json': 'b963324fde487b10de5c4e875d3b7fec7e56a7b518f13d03988b70ad45d09f06',
                                                                                'macos-wake-7f436366-69b7-4ddc-87b4-efb95478441a-transport.json': 'db4cd545205487172a082d919b03d7cb6849e978e6cbfca6b19c404824f4995a',
                                                                                'macos-wake-7f436366-69b7-4ddc-87b4-efb95478441a.json': '2d8adced9e7e3e8d357371e068d2a4cded64118ab2e9875f1bf6270a417e0f30'}},
 'prepared-bounded-Shift-incidents-3b6d3fa8-ce4a-47d0-88d7-abdd484e86c8': {'absent': [],
                                                                           'entries': ['approval-window.json',
                                                                                       'bounded-incident-wake.inert.py',
                                                                                       'incident.lock',
                                                                                       'incidents',
                                                                                       'plan.json'],
                                                                           'files': {'approval-window.json': '2a88b09a04a3af888c165e3059308efcdf1731d6c5d86cc69911bc171e9c092c',
                                                                                     'bounded-incident-wake.inert.py': '83247cadfe949ee7554780ea6d58b9ee6c1c7a4495e74d451e4b9ff4cd0999f7',
                                                                                     'plan.json': '820be6294f5a4ef9c7746125799f67a1d07eb341cd2774d41ec8eede53532dbd'},
                                                                           'incidentChildren': ['1626617e-1685-4c16-b0cb-324fbce4b3c2'],
                                                                           'kind': 'bounded_wake',
                                                                           'nested': {'incidents/1626617e-1685-4c16-b0cb-324fbce4b3c2': {'absent': [],
                                                                                                                                         'entries': ['independent-recognition.json',
                                                                                                                                                     'input-transport-complete.json',
                                                                                                                                                     'observation-pending.json',
                                                                                                                                                     'original-unknown.json',
                                                                                                                                                     'public-poll-1.png',
                                                                                                                                                     'public-poll-2.png'],
                                                                                                                                         'files': {'independent-recognition.json': '5d44aaae7dd6d072b8e1e23098639e6b159f22c2574d8dc0e34c7a33e9082b05',
                                                                                                                                                   'input-transport-complete.json': '3f7156666c30942381593f01570038dcf4efcddd203fa2d61dc9ff8d09c6fcc9',
                                                                                                                                                   'observation-pending.json': '8d023e5419fb71326476d330df6302bfb3975bc26652aae4ab459756e24e74dd',
                                                                                                                                                   'original-unknown.json': '8ea21e57cead0e553f17c0041e35b5ba7e79b5a8da793e10040c008b45a37cff'}}},
                                                                           'phaseFacts': [],
                                                                           'publicOriginal': None,
                                                                           'rootFiles': {}},
 'prepared-bounded-Shift-incidents-b738a8f3-dc6d-480c-94a2-7334f77d427e': {'absent': ['approval-window.json',
                                                                                      'incidents',
                                                                                      'original-unknown.json'],
                                                                           'entries': ['preparation-failure.json'],
                                                                           'files': {'preparation-failure.json': '10a04b1e850e714275252eea95af5ab0469867e9fbf1ff2d84fac37c44fde53a'},
                                                                           'kind': 'preparation_only',
                                                                           'nested': {},
                                                                           'phaseFacts': [],
                                                                           'publicOriginal': None,
                                                                           'rootFiles': {}},
 'prepared-single-leftshift-1c118802-129f-45b4-83f5-8686e5645f74': {'absent': ['original-unknown.json',
                                                                               'input-transport-complete.json'],
                                                                    'entries': ['plan.json',
                                                                                'public-preparation-source.py'],
                                                                    'files': {'plan.json': '8e499a0154a1203b08a4d9a3cb13c9dde2e7155c7048b71b0efdfe3a2c9ff5c2',
                                                                              'public-preparation-source.py': 'd3bb7b30b9e96e6ce5618f1427442ec6238f7b55dfb58dbcff9312b456c18d93'},
                                                                    'kind': 'inert_preparation',
                                                                    'nested': {},
                                                                    'phaseFacts': [],
                                                                    'publicOriginal': None,
                                                                    'rootFiles': {}},
 'prepared-single-leftshift-executable-e9a280b1-95f9-4ed7-8887-2ec4f1aaa3a0': {'absent': [],
                                                                               'entries': ['execute-leftshift-once.inert.py',
                                                                                           'independent-observation.json',
                                                                                           'input-transport-complete.json',
                                                                                           'observation-pending.json',
                                                                                           'original-unknown.json',
                                                                                           'plan.json',
                                                                                           'public-after-leftshift.png'],
                                                                               'files': {'execute-leftshift-once.inert.py': '17f04c7da9e5d0012743d39a92472f83c68ed8d674fada7f630743a710021b94',
                                                                                         'independent-observation.json': 'aa320fe4acf693e00dd581b775b0c79b8335993819511885779803ab46dd0eb4',
                                                                                         'input-transport-complete.json': '82407625b463e8e5edf8bb530a6a08063f5d3f19dd8b3b699830a3e958328ed2',
                                                                                         'observation-pending.json': '52602230b0bd429162e40c28c3ca0fcdf9327969f854b373594232bc40444c2a',
                                                                                         'original-unknown.json': '8caeafbaf42150494f95e4a5411294ce81859cd251f2131c38b6b60f2cc824a5',
                                                                                         'plan.json': '908c4702e7ee100ddb48a0b94982fc59ed7a1a7bfbcc07e0e3c74863bd2298bb'},
                                                                               'kind': 'finished',
                                                                               'nested': {},
                                                                               'phaseFacts': [{'file': 'input-transport-complete.json',
                                                                                               'operationId': 'e9a280b1-95f9-4ed7-8887-2ec4f1aaa3a0',
                                                                                               'state': 'submitted_awaiting_independent_screen_observation'}],
                                                                               'publicOriginal': None,
                                                                               'rootFiles': {}},
 'protected-UsersGroups-admin-auth-ad87285f-ea9a-4176-a53c-301a685ef946': {'absent': [],
                                                                           'entries': ['independent-authorization-observed.json',
                                                                                       'masked-public-observer-1792513370158200000.png',
                                                                                       'masked-public-observer-1792513386697402000.png',
                                                                                       'normal-admin-authorization.inert.py',
                                                                                       'plan.json',
                                                                                       'secret-inputs',
                                                                                       'secret-transport-complete.json',
                                                                                       'unlock-original-unknown.json',
                                                                                       'unlock-transport-complete.json'],
                                                                           'files': {'independent-authorization-observed.json': '20403683d28858a1e09b76b46d0cf8d3bd0b02abd9218cd956f7496fa4fb129e',
                                                                                     'normal-admin-authorization.inert.py': 'd069084e311c6874f4e4e7d8e83f8a398660d8e848156c745290c9ea55046d1b',
                                                                                     'plan.json': 'f12ab332013153fe9effb3af327e159c8017fa729361680f3661ad02972f3b24',
                                                                                     'secret-transport-complete.json': '93199b0459796a903186186748c39b1d2df770a762afc862dc850e5633a98595',
                                                                                     'unlock-original-unknown.json': '138235fc880dff7c8fe78cc418b2ee338571e9ab6619e02d2d3a7abb2bc11cb1',
                                                                                     'unlock-transport-complete.json': 'a81b8ef31628f25049dc3e537904190b073db4fb685e7281604dd845d32cd6a8'},
                                                                           'kind': 'finished',
                                                                           'nested': {},
                                                                           'phaseFacts': [{'file': 'secret-transport-complete.json',
                                                                                           'operationId': 'a230685e-c38f-4e4f-8eba-c4d4eb5feb84',
                                                                                           'state': 'transport_complete_not_authorization_receipt'},
                                                                                          {'file': 'unlock-transport-complete.json',
                                                                                           'operationId': '91ce2b8d-db90-4ec1-b9bb-3a060384ba72',
                                                                                           'state': 'awaiting_independent_public_page_observation'}],
                                                                           'publicOriginal': None,
                                                                           'rootFiles': {}},
 'protected-agent-log-preparation-admin-auth-2475e8e7-17ff-42ee-9695-3a46cbdbef6f': {'absent': [],
                                                                                     'entries': ['masked-public-observer-1792515925726196000.png',
                                                                                                 'masked-public-observer-1792515981824890000.png',
                                                                                                 'normal-agent-log-preparation-admin-authorization.inert.py',
                                                                                                 'plan.json',
                                                                                                 'public-root-repair-complete-observed.json',
                                                                                                 'secret-inputs',
                                                                                                 'secret-transport-complete.json',
                                                                                                 'unlock-original-unknown.json',
                                                                                                 'unlock-transport-complete.json'],
                                                                                     'files': {'normal-agent-log-preparation-admin-authorization.inert.py': '9a25113db8fd306a6c90a1232d29ef686e1ef59121db597932916fc1cb42a02b',
                                                                                               'plan.json': '6125e016b577bf574bccedc296743630edb387d419c433741aa9b2c3b10810f4',
                                                                                               'public-root-repair-complete-observed.json': 'e8766b5cf0cb7dfdf6fec589581c697831eff7a86b6f0e65edcd9ffd7d13ab75',
                                                                                               'secret-transport-complete.json': 'a1b7a8e3039811edc855db87ccb980177c514c67d6d2bb82c3fed44c4de475c3',
                                                                                               'unlock-original-unknown.json': '1f451833d1c8b7cf1d5eade8b87ea794950837793d5931581d6f21e3f447240f',
                                                                                               'unlock-transport-complete.json': 'c1bf0e581f50646f28d4fb1d3b94c0a2cd467d0abf985bc964f5ca67587920e8'},
                                                                                     'kind': 'finished',
                                                                                     'nested': {},
                                                                                     'phaseFacts': [{'file': 'secret-transport-complete.json',
                                                                                                     'operationId': 'ee5581cc-172d-4be1-9cfe-13dbc221965d',
                                                                                                     'state': 'transport_complete_not_authorization_receipt'},
                                                                                                    {'file': 'unlock-transport-complete.json',
                                                                                                     'operationId': 'c8fb52c6-acab-4035-9f1d-fbb66a9ae8fd',
                                                                                                     'state': 'awaiting_independent_public_page_observation'}],
                                                                                     'publicOriginal': None,
                                                                                     'rootFiles': {}},
 'protected-bootstrap-account-270c750b-5e48-4d91-a8d7-2d343f371fde': {'absent': [],
                                                                      'entries': ['account-submit-transport-complete.json',
                                                                                  'account-submit-unknown.json',
                                                                                  'bootstrapadmin-pass.bin',
                                                                                  'first-desktop-observed-closed.json',
                                                                                  'masked-public-observer-1792512775730381000.png',
                                                                                  'masked-public-observer-1792512803505187000.png',
                                                                                  'password-transport-complete.json',
                                                                                  'phase-started.json',
                                                                                  'phase.lock',
                                                                                  'plan.json',
                                                                                  'preparation-failure.json',
                                                                                  'protected-account-phase.inert.py',
                                                                                  'public-post-account-classification.json',
                                                                                  'secret-inputs',
                                                                                  'verify-transport-complete.json'],
                                                                      'files': {'account-submit-transport-complete.json': '0f75a8a4c0d9b331875fdd13f768c752bb8a6283ad39dfbdaeb976eaaf710d3e',
                                                                                'account-submit-unknown.json': 'bb5dff9a72630e1064d58e13ed98836e8e054d05068a875314c1fe4835ca9899',
                                                                                'first-desktop-observed-closed.json': '8180722830fd81958c2c97ce3e8790c983814aa9a7fb3b4e2179d58e19a36a08',
                                                                                'password-transport-complete.json': 'cf7f21a0d9d8a6b7eb7471a2d1e9db5002fc0cd50788bdd7a45654ff764ea062',
                                                                                'phase-started.json': 'e3f8921e9f5740fc234368bd038820c47b01360afc1cdc9782a441d941b59f2d',
                                                                                'plan.json': '2e041e45bc0792a5d00a1826349857ccda3fc963ad53437ec54d03ef2001fca3',
                                                                                'preparation-failure.json': 'a661a896bbb9c44755e56efda93122bc804d2eba6530317f5435631dae74b8a1',
                                                                                'protected-account-phase.inert.py': '3cc84be01476ff33464d14ebb8033ec2e022ce048e7a886643ccb3896071f53e',
                                                                                'public-post-account-classification.json': 'a393cf869a705fdb2844862831c299d857b0a98df3ac5d4dc7e1e5a64938bb85',
                                                                                'verify-transport-complete.json': 'f5a908c34c56079b461cdcfdf807d5be1bc341d0c1405098a7dcdb10c8438770'},
                                                                      'kind': 'finished',
                                                                      'nested': {},
                                                                      'phaseFacts': [{'file': 'account-submit-transport-complete.json',
                                                                                      'operationId': '60e20be2-e5e1-4c75-bd71-0063b6f46fe1',
                                                                                      'state': 'submitted_awaiting_independent_post_account_observation'},
                                                                                     {'file': 'password-transport-complete.json',
                                                                                      'operationId': '3ce1eb8e-72d1-45ce-bd97-564b982b0016',
                                                                                      'state': 'input_transport_complete_not_account_receipt'},
                                                                                     {'file': 'verify-transport-complete.json',
                                                                                      'operationId': 'b42fc9ca-93a2-4459-941f-69a6d29efb8d',
                                                                                      'state': 'input_transport_complete_not_account_receipt'}],
                                                                      'publicOriginal': None,
                                                                      'rootFiles': {}},
 'protected-continuation-admin-auth-d732e50b-341e-428c-9947-79fa69bb648e': {'absent': ['unlock-original-unknown.json',
                                                                                       'unlock-transport-complete.json'],
                                                                            'entries': ['current-field-continuation.lock',
                                                                                        'masked-observer-after-unsubmitted-guard-1792514998166268000.png',
                                                                                        'masked-public-observer-1792514572788552000.png',
                                                                                        'masked-public-observer-1792515107896524000.png',
                                                                                        'masked-public-observer-1792515146840641000.png',
                                                                                        'normal-continuation-admin-authorization.inert.py',
                                                                                        'original-public-backdrop-guard-failure-1792514726779198000',
                                                                                        'original-stopped-before-submit.json',
                                                                                        'plan.json',
                                                                                        'public-guard-repeat-comparison-1792514998166268000.png',
                                                                                        'public-post-authorization-classification.json',
                                                                                        'public-recipient-crops-before-vs-current.png',
                                                                                        'readonly-public-recipient-difference.json',
                                                                                        'secret-inputs',
                                                                                        'secret-transport-complete.json',
                                                                                        'submit-existing-filled-field-adbe3797-9dd4-4347-885f-8410f1a12dd0',
                                                                                        'submit-existing-filled-field-cc5ef82f-0e7e-48a9-8365-cb1bbe763887',
                                                                                        'unsubmitted-recipient-guard-diagnostic-1792514998166268000.json'],
                                                                            'files': {'normal-continuation-admin-authorization.inert.py': '45e3ef74f6dcf23fef8675170b5d1c2aa16d281989556db926cdcd02d978a77c',
                                                                                      'original-stopped-before-submit.json': 'fbc379ca1c85c839e539a1791d7abca3fc1ed92d6b12d735e015043265860112',
                                                                                      'plan.json': 'a0485d2164e805ac09973cf07a6c38b57397d50ee8cf5d866a7990c8a1e539f0',
                                                                                      'public-post-authorization-classification.json': '597ad4744cbd78ce2d781e9e46386183012a8b6f40f1c8ae95d5ba3edfebb13d',
                                                                                      'readonly-public-recipient-difference.json': '717278975d12499509f3ada810afed8d4a0c3dc4d04a790a42b3716f0c03dcb3',
                                                                                      'secret-transport-complete.json': '6d2fc39ca3f3f403212ccf3fb16da52b0eafa9011eb109f51dc62a4ff7f9a338',
                                                                                      'unsubmitted-recipient-guard-diagnostic-1792514998166268000.json': '6efdcccc3f967466ef33466e81e6314bca501f5f7200e0f0de391d33e5a81bee'},
                                                                            'kind': 'continuation',
                                                                            'nested': {'submit-existing-filled-field-adbe3797-9dd4-4347-885f-8410f1a12dd0': {'absent': ['submit-original-unknown.json',
                                                                                                                                                                        'submit-transport-complete.json'],
                                                                                                                                                             'entries': ['plan.json',
                                                                                                                                                                         'proven-unsubmitted-background-classifier-block.json',
                                                                                                                                                                         'submit-existing-field-once.inert.py'],
                                                                                                                                                             'files': {'plan.json': '08d8b04bd3bae43a7624590a09d8c89a32272b496509caa9772a9737b5a7cbd5',
                                                                                                                                                                       'proven-unsubmitted-background-classifier-block.json': '10943c621db057c9a52482b3be7ce8248a6524fc1b786cef41d1d1655367a5e3',
                                                                                                                                                                       'submit-existing-field-once.inert.py': '161a53ea40646a5627fe466c40442a01b3ed65c9f8a8a5d0f1a09b244eee8feb'}},
                                                                                       'submit-existing-filled-field-cc5ef82f-0e7e-48a9-8365-cb1bbe763887': {'absent': [],
                                                                                                                                                             'entries': ['plan.json',
                                                                                                                                                                         'submit-existing-field-once.inert.py',
                                                                                                                                                                         'submit-original-unknown.json',
                                                                                                                                                                         'submit-transport-complete.json'],
                                                                                                                                                             'files': {'plan.json': '92033cf3c0f3d7f0d02bb2541da8d21a32544a1017d61975fb0ed6c7b4ce962e',
                                                                                                                                                                       'submit-existing-field-once.inert.py': '630d3e7264ba39d9d58c8dd923bb4bc9d63092de949ed4076f943e5e04b2a924',
                                                                                                                                                                       'submit-original-unknown.json': 'afd26e6af6b1c12fe5c7f6c58ffa9b7e6e440872d6e192bb87ef54457324f0fb',
                                                                                                                                                                       'submit-transport-complete.json': '6e68e97fedb92d453a8bfe6627479be61376b83b396f9dc0297127a74a20af49'}}},
                                                                            'phaseFacts': [{'file': 'secret-transport-complete.json',
                                                                                            'operationId': 'a5e3a2d0-6ade-498b-abab-a076a260dd4e',
                                                                                            'state': 'transport_complete_not_authorization_receipt'}],
                                                                            'publicOriginal': None,
                                                                            'rootFiles': {}},
 'protected-ordinary-first-login-4cdfbaee-d2aa-42f4-865e-1479d9a266bd': {'absent': ['secret-inputs',
                                                                                    'password-transport-complete.json',
                                                                                    'submit-unknown.json',
                                                                                    'submit-transport-complete.json'],
                                                                         'entries': ['empty-field-readonly-timing-facts.json',
                                                                                     'ordinary-login-once.inert.py',
                                                                                     'original-preinput-failure.json',
                                                                                     'phase-unknown.json',
                                                                                     'phase.lock',
                                                                                     'public-known-empty-caret-sample-1.png',
                                                                                     'public-known-empty-caret-sample-3.png',
                                                                                     'public-known-empty-caret-sample-5.png',
                                                                                     'review-plan.json'],
                                                                         'files': {'empty-field-readonly-timing-facts.json': '4cd9faefb7186f3cf59c980b1aaa5c63bbf899d431186b9505ec580594534849',
                                                                                   'ordinary-login-once.inert.py': '1de0cfabdeac014369d5e26e60327302e3dda23ffed322f26fe955c228a49ab9',
                                                                                   'original-preinput-failure.json': '059ad5fb70b0f485bd0280e333bc42c732f97b49ea92f38e1f1d630bca253074',
                                                                                   'phase-unknown.json': '11b2e7b309544c1cbdf6137a795dca08bac9984974fa9c47a581906362305ba3',
                                                                                   'review-plan.json': '0388c9aad8b2f2d8956a382c438741829e44f57cdedacd3deb27f0db66091504'},
                                                                         'kind': 'before_secret_guard',
                                                                         'nested': {},
                                                                         'phaseFacts': [],
                                                                         'publicOriginal': None,
                                                                         'rootFiles': {}},
 'protected-ordinary-first-login-adb88bf8-ef8e-41f1-b827-e365146d081b': {'absent': [],
                                                                         'entries': ['independent-ordinary-desktop-observed.json',
                                                                                     'masked-login-observer-1792516712117730000.png',
                                                                                     'masked-login-observer-1792516727760471000.png',
                                                                                     'ordinary-login-once.inert.py',
                                                                                     'password-transport-complete.json',
                                                                                     'phase-unknown.json',
                                                                                     'phase.lock',
                                                                                     'review-plan.json',
                                                                                     'secret-inputs',
                                                                                     'submit-transport-complete.json',
                                                                                     'submit-unknown.json'],
                                                                         'files': {'independent-ordinary-desktop-observed.json': '1f8a64def9b2d16f891727ef34935731ec8957b5bfd48dc5be8444335851909b',
                                                                                   'ordinary-login-once.inert.py': '67ef44ac163a692bc22476903fb26ce1c963d7a0ce25745fec4dd64dc95895ca',
                                                                                   'password-transport-complete.json': 'a0614e444444bf6ae019b0a986998d6d014506bdcce8f2e292aed49f94fa842f',
                                                                                   'phase-unknown.json': 'b902dbbf8f93485baddf08d3c847f2e9c9db9f596de412ca9cfc54e3f24f8221',
                                                                                   'review-plan.json': '6a21d1b15f97ff34d885f264a7cbcb301fd5d58482af4daccfc0779cecd47077',
                                                                                   'submit-transport-complete.json': '57bc8d10aa9e8ff22eccd15d90323656b59ba162e4bd84eec835aa247541c961',
                                                                                   'submit-unknown.json': 'bfa4420a45cd0e660406f873961c5432e048706ba90930f9ff4b8c48cb8ac8ce'},
                                                                         'kind': 'finished',
                                                                         'nested': {},
                                                                         'phaseFacts': [{'file': 'password-transport-complete.json',
                                                                                         'operationId': '704df4f4-97c0-4efd-8f2b-e76563fe046e',
                                                                                         'state': 'transport_complete_not_login_receipt'},
                                                                                        {'file': 'submit-transport-complete.json',
                                                                                         'operationId': '728b5600-26f3-4da9-b9c0-f4dc0e5ca789',
                                                                                         'state': 'submitted_awaiting_independent_session'}],
                                                                         'publicOriginal': None,
                                                                         'rootFiles': {}},
 'protected-pinned-bootstrap-admin-auth-dd31ba2c-a2e5-4895-b821-cafcabc99d53': {'absent': [],
                                                                                'entries': ['masked-public-observer-1792513852803344000.png',
                                                                                            'masked-public-observer-1792513878643744000.png',
                                                                                            'normal-bootstrap-admin-authorization.inert.py',
                                                                                            'plan.json',
                                                                                            'secret-inputs',
                                                                                            'secret-transport-complete.json',
                                                                                            'unlock-original-unknown.json',
                                                                                            'unlock-transport-complete.json'],
                                                                                'files': {'normal-bootstrap-admin-authorization.inert.py': 'b9842ac715a0c8867a71475d07b86cef019a410e0814478934f0de1d6d8487b6',
                                                                                          'plan.json': '82b6b7118ff6ccc5b6c662971051d1532f808d0bd7cca69ae80de1e2802d8da0',
                                                                                          'secret-transport-complete.json': 'ce477bbde6266dc4c89493bc39d81994bd2f1b6b9b2d0b99efc8fce781576573',
                                                                                          'unlock-original-unknown.json': '62683e768b0deb0fab503713b82b56de71aac84dfe2448f349e8e20993c71952',
                                                                                          'unlock-transport-complete.json': '4bc4ce56c81881b5f42b198ca873db06a27c954ab67bf16158423c2f9b01e49b'},
                                                                                'kind': 'finished',
                                                                                'nested': {},
                                                                                'phaseFacts': [{'file': 'secret-transport-complete.json',
                                                                                                'operationId': 'bd0c61ae-e367-42a6-9bb6-4fd9987ea7bc',
                                                                                                'state': 'transport_complete_not_authorization_receipt'},
                                                                                               {'file': 'unlock-transport-complete.json',
                                                                                                'operationId': '2f38a56d-7b73-4db1-acd7-644a3b1258a8',
                                                                                                'state': 'awaiting_independent_public_page_observation'}],
                                                                                'publicOriginal': None,
                                                                                'rootFiles': {}},
 'protected-standard-account-8b3966a1-2379-4a59-b99a-9f061a7e8d9c': {'absent': [],
                                                                     'entries': ['account-submit-transport-complete.json',
                                                                                 'account-submit-unknown.json',
                                                                                 'independent-standard-account-created.json',
                                                                                 'masked-public-observer-1792513514540536000.png',
                                                                                 'masked-public-observer-1792513533740177000.png',
                                                                                 'ordinary-pass.bin',
                                                                                 'password-transport-complete.json',
                                                                                 'phase-started.json',
                                                                                 'phase.lock',
                                                                                 'plan.json',
                                                                                 'protected-standard-account-phase.inert.py',
                                                                                 'secret-inputs',
                                                                                 'verify-transport-complete.json'],
                                                                     'files': {'account-submit-transport-complete.json': '5dcf9f8396882ec0b5507875cbcfa030b79a837100dcf24e8c6ddfb1996ab00f',
                                                                               'account-submit-unknown.json': '811bf01a54af729b93223c4704fb01a41e3ba74077538b38df8eaf304a5883dd',
                                                                               'independent-standard-account-created.json': '0a15fc7376e84a74e9b352261a3e2e5049b26be5fb1ca56f70d8c52e42f57577',
                                                                               'password-transport-complete.json': 'b3bc73403f26fb0b4ae7dd8962c19c8844333e2c5855e917e056c24233175cb6',
                                                                               'phase-started.json': '80534a387732313a4f1045067492870cac22cc55c3a5c62bbb59e6f10001af3a',
                                                                               'plan.json': '2b1a0ead6aa3fd81e2a874ce1f77cfd45e8c9d97522c440a7bdca8bc1617850e',
                                                                               'protected-standard-account-phase.inert.py': '711306cb50dc7024084128f95937a46953ea7b0b88688603bdfc77efe5a0720c',
                                                                               'verify-transport-complete.json': 'f60d127f710d48f9f0b11a08cade2b26e8c98a4b7e1caea5d34ce9616035b47d'},
                                                                     'kind': 'finished',
                                                                     'nested': {},
                                                                     'phaseFacts': [{'file': 'account-submit-transport-complete.json',
                                                                                     'operationId': '054a2430-852c-4f09-a348-7c57fc30c7b3',
                                                                                     'state': 'submitted_awaiting_independent_post_account_observation'},
                                                                                    {'file': 'password-transport-complete.json',
                                                                                     'operationId': '72f1707c-d74d-4efb-bfe3-fa1e54cccb35',
                                                                                     'state': 'input_transport_complete_not_account_receipt'},
                                                                                    {'file': 'verify-transport-complete.json',
                                                                                     'operationId': '8535b418-8e59-4cc9-9955-ec7d7f64f7b4',
                                                                                     'state': 'input_transport_complete_not_account_receipt'}],
                                                                     'publicOriginal': None,
                                                                     'rootFiles': {}},
 'protected-state-bound-unlock-bff007a4-0f32-4e7d-a841-2b8b3482d8aa': {'absent': [],
                                                                       'entries': ['independent-session.json',
                                                                                   'password-transport-complete.json',
                                                                                   'phase-unknown.json',
                                                                                   'plan.json',
                                                                                   'public-preflight.json',
                                                                                   'secret-inputs',
                                                                                   'submit-transport-complete.json',
                                                                                   'submit-unknown.json',
                                                                                   'unlock-once.inert.py',
                                                                                   'unlock-qualified.inert.py'],
                                                                       'files': {'independent-session.json': 'b6885e412c603636ebe3d31b8f305ce9dcf6f5ac82559f739804304ae36f6f5c',
                                                                                 'password-transport-complete.json': 'b1cfbfd4a82a42bd2e30fd6d42ebd98ff725e38c862abb4c18b0194cd3dfebd7',
                                                                                 'phase-unknown.json': '0b7fdae6a8514c4ad38f42b3237dacb543dd6310349cea0351701a3ef8f8218d',
                                                                                 'plan.json': '05e3d2d4fe386f66b60a5bd0e2e6d627afd06c6e07afa460ae7107189e418fca',
                                                                                 'public-preflight.json': 'a24c5569acd2b5c0a0d151e1b5a15beeba8814f2d92213009abfba9f3e555780',
                                                                                 'submit-transport-complete.json': 'd02a18a364a8c62077681b28f2fde03cb942779926401dd32458b954143f429a',
                                                                                 'submit-unknown.json': '7434fa1d603aa70b535c2a7b36540df20d04ef171df66ac7932c6cc51d0e00b0',
                                                                                 'unlock-once.inert.py': '032d5c6966d1ed15f486a828b990cf7ef0bbacff419b46ec012d222f249b6267',
                                                                                 'unlock-qualified.inert.py': '80ac36469ccac1e241b44d4b4e6c90d382845b3fdd98afd8d6144681a0d8a39d'},
                                                                       'kind': 'finished',
                                                                       'nested': {},
                                                                       'phaseFacts': [{'file': 'password-transport-complete.json',
                                                                                       'operationId': 'bc7e5446-7c50-4256-9b3b-a0df73276cb4',
                                                                                       'state': 'transport_complete_not_unlock_receipt'},
                                                                                      {'file': 'submit-transport-complete.json',
                                                                                       'operationId': '7b9bebe8-190d-426d-bf99-9bacb79776c8',
                                                                                       'state': 'submitted_awaiting_independent_session'}],
                                                                       'publicOriginal': None,
                                                                       'rootFiles': {}}}


def _need(value, reason):
    if not value: raise qualification.QualificationBlocked(reason)


def _absence(directory, names):
    directory.guard()
    for name in names:
        _need(type(name) is str and Path(name).name == name, 'macos_legacy_phase_route_invalid')
        try: os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise qualification.QualificationBlocked('macos_legacy_before_phase_absence_unproven')
    directory.guard()


def _files(directory, expected, stack, holders):
    values = {}
    for name, digest in expected.items():
        _need(Path(name).name == name and name.endswith(('.py', '.json')),
              'macos_legacy_phase_route_invalid')
        item = stack.enter_context(private.Snapshot(directory, name)); holders.append(item)
        _need(item.digest == digest, 'macos_legacy_phase_original_changed')
        values[name] = qualification._json(item.body) if name.endswith('.json') else item.body
    return values


def _secret_release_contract():
    source = Path(rfb.__file__).read_bytes()
    _need(hashlib.sha256(source).hexdigest() in public._LIVE_RFB_SHAS, 'macos_legacy_method_epoch_unqualified')
    public._method_contract(source)
    def codes(code):
        yield code
        for value in code.co_consts:
            if isinstance(value, CodeType): yield from codes(value)
    compiled = compile(source, rfb.__file__, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    expected = next(code for code in codes(compiled)
                    if code.co_qualname == 'ProtectedVncSession.type_secret_from_fd')
    _need(inspect.unwrap(rfb.ProtectedVncSession.type_secret_from_fd).__code__ == expected,
          'macos_legacy_method_epoch_unqualified')


def _source_contract(stack, holders, custody):
    # A short-lived per-original proof may close after validation. Keep the
    # shared source generations open for the complete aggregate proof too.
    for module in (inventory, public):
        path = Path(module.__file__)
        raw = path.read_bytes()
        _need(module._EXECUTING_CODE == compile(raw, str(path), 'exec', dont_inherit=True,
              optimize=sys.flags.optimize), 'macos_legacy_phase_source_changed')
        holders.append(public._hold(path, hashlib.sha256(raw).hexdigest(), stack, private_file=False))
    holders.append(public._hold_method_source(stack))
    helper = custody.root / '.runtime/tool-recovery/tart/macos-provision-ui-helper.py'
    holders.append(public._hold(helper, public._FIXED_HELPER_SHA, stack))
    _secret_release_contract()


def _journal_metadata(custody, root, stack, holders):
    selected = {name for name, spec in _CASES.items() if 'secret-inputs' in spec['entries']}
    if not selected: return []
    original = stack.enter_context(private.Snapshot(root, _SCAFFOLD_NAME)); holders.append(original)
    _need(original.digest == _SCAFFOLD_SHA, 'macos_legacy_journal_metadata_unqualified')
    value = qualification._json(original.body)
    _need(value['originalRun'] == _ORIGINAL_RUN and value['readSecretInputDirectories'] is False,
          'macos_legacy_journal_metadata_unqualified')
    matched = set(); journal_rows = []
    for container in value['containers']:
        if container['directory'] not in selected: continue
        rows = [row for row in container['entries'] if row['name'] == 'secret-inputs']
        _need(len(rows) == 1, 'macos_legacy_journal_metadata_unqualified')
        row = rows[0]
        # Inspect the directory entry itself, never its entries or private
        # journal contents. A new hidden input incident changes this generation.
        journal_rows.append((container['directory'], row))
        matched.add(container['directory'])
    _need(matched == selected, 'macos_legacy_journal_metadata_unqualified')
    _journal_guard(custody, journal_rows)
    return journal_rows


def _journal_guard(custody, rows):
    for directory, row in rows:
        info = (custody.lifecycle_root / directory / 'secret-inputs').lstat()
        actual = {'device': info.st_dev, 'inode': info.st_ino, 'mode': stat.S_IMODE(info.st_mode),
                  'uid': info.st_uid, 'nlink': info.st_nlink, 'size': info.st_size,
                  'mtimeNs': info.st_mtime_ns, 'ctimeNs': info.st_ctime_ns}
        _need(stat.S_ISDIR(info.st_mode) and all(actual[key] == row[key] for key in actual),
              'macos_legacy_journal_generation_changed')


def _case(custody, name, spec, stack, holders, listings, absences):
    directory = stack.enter_context(private.Directory(custody.lifecycle_root / name)); holders.append(directory)
    metadata = inventory._metadata(directory)
    _need(sorted(item[0] for item in metadata) == spec['entries'], 'macos_legacy_phase_inventory_changed')
    listings.append((directory, metadata)); _absence(directory, spec['absent']); absences.append((directory, spec['absent']))
    values = _files(directory, spec['files'], stack, holders)
    roots = _files(stack.enter_context(private.Directory(custody.lifecycle_root)), spec['rootFiles'], stack, holders)
    nested_values = {}
    for relative, nested in spec['nested'].items():
        path = Path(relative)
        _need(not path.is_absolute() and '..' not in path.parts and all(part not in {'secret-inputs', '.'} for part in path.parts),
              'macos_legacy_phase_route_invalid')
        child = stack.enter_context(private.Directory(directory.path / path)); holders.append(child)
        child_metadata = inventory._metadata(child)
        _need(sorted(row[0] for row in child_metadata) == nested['entries'], 'macos_legacy_phase_inventory_changed')
        listings.append((child, child_metadata)); _absence(child, nested['absent']); absences.append((child, nested['absent']))
        nested_values[relative] = _files(child, nested['files'], stack, holders)
    for fact in spec['phaseFacts']:
        actual = values[fact['file']]
        _need(actual['operationId'] == fact['operationId'] and actual['state'] == fact['state'],
              'macos_legacy_phase_original_changed')
        inventory._uuid(actual['operationId'])
    kind = spec['kind']
    if kind == 'archive':
        proof = public.observe(custody, spec['publicOriginal'])
        try:
            _need(proof.report['workState'] == 'transport_finished', 'macos_legacy_archive_original_unresolved')
        finally: proof.close()
        state = 'evidence_archive_no_additional_admission'
    elif kind in {'preparation_only', 'inert_preparation', 'before_secret_guard'}:
        _need(bool(spec['absent']), 'macos_legacy_before_phase_absence_unproven')
        state = 'proven_unsubmitted'
    elif kind == 'continuation':
        secret = values['secret-transport-complete.json']['operationId']
        submit_name = next(key for key in nested_values if key.startswith('submit-existing-filled-field-cc5'))
        submit = nested_values[submit_name]
        _need(submit['submit-original-unknown.json']['originalSecretOperation'] == secret
              and submit['submit-original-unknown.json']['operationId'] == submit['submit-transport-complete.json']['operationId'],
              'macos_legacy_continuation_original_changed')
        # Exact admitted source630d has no secret input call. It submits the
        # already-typed original field, never retypes a credential.
        source = submit['submit-existing-field-once.inert.py']
        _need(not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                      and node.func.attr == 'type_secret_from_fd' for node in ast.walk(ast.parse(source))),
              'macos_legacy_continuation_retype_unqualified')
        state = 'secret_and_final_submit_finished_prior_submits_unsubmitted'
    elif kind == 'bounded_wake':
        incidents = stack.enter_context(private.Directory(directory.path / 'incidents')); holders.append(incidents)
        _need(sorted(os.listdir(incidents.fd)) == spec['incidentChildren'], 'macos_legacy_phase_inventory_changed')
        listings.append((incidents, inventory._metadata(incidents)))
        approval = values['approval-window.json']
        _need(approval['targetRun'] == _ORIGINAL_RUN and type(approval['expires']) in {int, float}
              and approval['expires'] < time.time(), 'macos_legacy_approval_not_closed')
        for packet in nested_values.values():
            _need(packet['original-unknown.json']['operationId'] == packet['input-transport-complete.json']['operationId'],
                  'macos_legacy_phase_original_changed')
        state = 'one_shift_transport_finished_unused_approval_expired'
    else:
        _need(kind == 'finished' and (spec['phaseFacts'] or spec['rootFiles']
              or 'input-transport-complete.json' in values), 'macos_legacy_phase_protocol_unqualified')
        for filename, receipt in roots.items():
            if filename.endswith('-transport.json'):
                _need(receipt['state'] == 'input_group_transport_closed', 'macos_legacy_phase_original_changed')
        state = 'input_transport_finished'
    return {'family': name, 'inputWorkState': state, 'semanticOutcome': 'preserved_not_inferred',
            'sourcePins': dict(spec['files']), 'rootRecordPins': dict(spec['rootFiles']),
            'beforePhaseAbsences': list(spec['absent']), 'replayForbidden': True,
            'historicalControllerPidBirth': 'not_retained_no_process_terminal_or_idle_claim',
            'oldObserverEnvelope': 'not_retained_historical_data_only' if name.startswith('protected-state-bound-unlock-bff') else 'not_used',
            'newNonceQualificationAuthority': False}


class LegacyInputClosure:
    def __init__(self, *args, **kwargs):
        raise qualification.QualificationBlocked('macos_legacy_phase_factory_required')

    def guard(self):
        _need(getattr(self, '_token', None) is _TOKEN and not self._closed, 'macos_legacy_phase_proof_closed')
        self._custody._operator.guard()
        _need(self._custody.lifecycle_root == self._root.path
              and self._custody.run_intent['operationId'] == _ORIGINAL_RUN
              and self._custody.actor == self._actor and self._custody.binding == self._binding,
              'macos_legacy_phase_target_changed')
        for holder in self._holders: holder.guard()
        for directory, metadata in self._listings:
            _need(inventory._metadata(directory) == metadata, 'macos_legacy_phase_inventory_changed')
        for directory, names in self._absences: _absence(directory, names)
        _journal_guard(self._custody, self._journal_rows)
        _need({name for name in os.listdir(self._root.fd)
               if any(re.fullmatch(pattern, name) for pattern in inventory._FAMILIES)} == self._names,
              'macos_legacy_phase_inventory_changed')
        _secret_release_contract()

    @property
    def report(self): self.guard(); return deepcopy(self._report)

    def require_input_closed(self):
        self.guard()
        _need(self._report['inputPhaseClosed'] is True, 'macos_legacy_input_original_unresolved')

    def close(self):
        if not getattr(self, '_closed', True): self._closed = True; self._stack.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


def observe(custody):
    """No guest call/credential access; selected custody and qualified cases only."""
    _need(type(custody) is registry.MacCustody and custody.run_intent['operationId'] == _ORIGINAL_RUN,
          'macos_legacy_phase_original_run_unqualified')
    custody._operator.guard(); stack = ExitStack()
    try:
        path = Path(__file__); source = path.read_bytes()
        _need(_EXECUTING_CODE == compile(source, __file__, 'exec', dont_inherit=True,
              optimize=sys.flags.optimize), 'macos_legacy_phase_source_changed')
        own = stack.enter_context(registry.PublicProof(path, {'generation': list(private._generation(path.lstat())),
            'sha256': hashlib.sha256(source).hexdigest()}, private_file=False))
        root = stack.enter_context(private.Directory(custody.lifecycle_root))
        holders, listings, absences = [own, root], [], []
        expected = set(_CASES) | {'public-transitions'}
        _need({name for name in os.listdir(root.fd)
               if any(re.fullmatch(pattern, name) for pattern in inventory._FAMILIES)} == expected,
              'macos_legacy_phase_inventory_changed')
        _source_contract(stack, holders, custody)
        journal_rows = _journal_metadata(custody, root, stack, holders)
        public_directory = stack.enter_context(private.Directory(custody.lifecycle_root / 'public-transitions'))
        holders.append(public_directory); listings.append((public_directory, inventory._metadata(public_directory)))
        original_names = sorted(name for name in os.listdir(public_directory.fd) if inventory._INTENT.fullmatch(name))
        reports = []
        for name in original_names:
            # Validate each source-qualified original through the existing
            # opaque factory, then retain shared-directory record snapshots.
            # This avoids duplicating source/ancestry FDs64 times.
            proof = public.observe(custody, name[:-5])
            try:
                report = proof.report
                for suffix in ('.json', '-transport-closed.json'):
                    filename = name[:-5] + suffix
                    try: item = stack.enter_context(private.Snapshot(public_directory, filename))
                    except FileNotFoundError:
                        _need(suffix != '.json' and report['workState'] == 'proven_unsubmitted',
                              'macos_legacy_input_original_unresolved'); continue
                    holders.append(item)
                    if suffix == '.json': _need(item.pin() == report['originalPins']['intent'], 'macos_legacy_phase_original_changed')
                    else: _need(item.pin() == report['originalPins']['transport'], 'macos_legacy_phase_original_changed')
                reports.append(report)
            finally: proof.close()
        _need(bool(reports), 'macos_legacy_phase_inventory_changed')
        families = [_case(custody, name, spec, stack, holders, listings, absences) for name, spec in sorted(_CASES.items())]
        result = object.__new__(LegacyInputClosure)
        result._token, result._closed, result._stack, result._custody = _TOKEN, False, stack, custody
        result._actor, result._binding = deepcopy(custody.actor), deepcopy(custody.binding)
        result._journal_rows = journal_rows
        result._root, result._holders, result._listings, result._absences, result._names = root, holders, listings, absences, expected
        result._report = {'schemaVersion': 1, 'originalRun': _ORIGINAL_RUN, 'target': custody.binding.target,
            'machine': custody.binding.machine, 'resolverSha256': hashlib.sha256(source).hexdigest(),
            'publicOriginals': reports, 'families': families, 'inputPhaseClosed': True,
            'historicalSemanticSuccessInferred': False, 'processIdleAuthority': False,
            'replayForbidden': True, 'newNonceQualificationAuthority': False}
        result.guard(); return result
    except BaseException:
        stack.close(); raise


def resolve(custody):
    """Append a freshly revalidated original-only cache; never rewrite history."""
    with observe(custody) as proof:
        value = proof.report; path = custody.lifecycle_root / 'legacy-input-phase-resolutions'
        try: path.mkdir(mode=0o700)
        except FileExistsError: pass
        with private.Directory(path) as directory:
            name = _ORIGINAL_RUN + '.json'
            try:
                with private.Snapshot(directory, name) as existing:
                    _need(qualification._json(existing.body) == value, 'macos_legacy_phase_resolution_conflict')
            except FileNotFoundError:
                proof.guard(); fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                          0o600, dir_fd=directory.fd)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()); stream.flush(); os.fsync(stream.fileno())
                os.fsync(directory.fd)
            directory.guard(); proof.guard()
        return value
