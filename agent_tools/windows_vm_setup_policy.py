"""Retire attempt-specific VM constructors while retaining original observers.

These entry points describe purged historical fixtures, not reusable defaults.
Their implementations remain intact for preserved-source causal tests and the
original status/collection paths. No old job or reservation is rewritten.
"""
from __future__ import annotations

RETIRED_SETUP_ACTIONS = frozenset((
    'windows-parallel-vm-copy-start',
    'windows-vm-disk-probe-start',
    'windows-vm-driver-fetch-start',
    'windows-vm-fresh-preflight',
    'windows-vm-fresh-screen-start',
    'windows-vm-fresh-start',
    'windows-vm-optical-attempt2-close-preflight',
    'windows-vm-optical-attempt2-close-start',
    'windows-vm-optical-attempt2-preflight',
    'windows-vm-optical-attempt2-start',
    'windows-vm-optical-attempt3-preflight',
    'windows-vm-optical-attempt3-start',
    'windows-vm-optical-boot-preflight',
    'windows-vm-optical-boot-start',
    'windows-vm-optical-close-preflight',
    'windows-vm-optical-close-start',
    'windows-vm-optical-current-screen-preflight',
    'windows-vm-optical-current-screen-start',
    'windows-vm-secureboot-clone-preflight',
    'windows-vm-secureboot-fresh-preflight',
    'windows-vm-secureboot-fresh-start',
    'windows-vm-setup-install-ack-preflight',
    'windows-vm-setup-install-ack-start',
    'windows-vm-setup-install-focus-preflight',
    'windows-vm-setup-install-focus-start',
    'windows-vm-setup-install-next-preflight',
    'windows-vm-setup-install-next-start',
    'windows-vm-setup-keyboard-next-preflight',
    'windows-vm-setup-keyboard-next-start',
    'windows-vm-setup-language-next-preflight',
    'windows-vm-setup-language-next-start',
    'windows-vm-swtpm-repair-preflight',
    'windows-vm-swtpm-repair-start',
    'windows-vm-virt-firmware-admission',
    'windows-vm-virt-firmware-install-preflight',
    'windows-vm-virt-firmware-install-start',
))


HISTORICAL_FAMILIES=('windows-cp117-','windows-fixture-','windows-msi-',
                     'windows-vm-','windows-parallel-vm-','windows-update-fixture-')
RETIRED_UNBOUND_DISCOVERY=frozenset(('windows-vm-baseline-inventory','windows-vm-media-fingerprint',
                                     'windows-msi-base-start-from-transfer'))
# These adapters multiplex new submissions and original reads under one action.
# Keep the latter available; a phase name must not bypass the new-work fence.
RETIRED_TRANSFER_PHASES={
    'windows-msi-http-transfer':frozenset(('prepare','stage-start','listener-start','guest-download')),
    'windows-update-fixture-http-transfer':frozenset(('prepare','stage-start','listener-start','guest-create','guest-download','stage-extract')),
}



def refusal(action,inputs=None):
    # The generic deployment API and package-only CI fixture producer have
    # explicit inputs and no historical guest defaults. Named input/credential
    # primitives are outside these historical campaign families.
    if action.startswith(('windows-vm-deploy-','windows-msi-fixture-')):return None
    if action in RETIRED_SETUP_ACTIONS:reason='historical_windows_vm_setup_retired'
    elif (action in RETIRED_UNBOUND_DISCOVERY or action.startswith(HISTORICAL_FAMILIES) and action.endswith(('-start','-rebase'))
          or action in RETIRED_TRANSFER_PHASES and type(inputs)is dict and type(inputs.get('phase'))is str and inputs['phase'] in RETIRED_TRANSFER_PHASES[action]):
        reason='historical_windows_profile_retired'
    else:return None
    return {"tool": "vm_workflow", "ok": False, "state": "blocked",
            "reason": reason,
            "action": action, "nativeActionAllowed": False,
            "replayAllowed": False, "productAction": False,
            "nextAction": "windows-vm-deploy-preflight"}
