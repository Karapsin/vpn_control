"""Copy a fixture environment for the explicitly named PowerShell runtime.

Windows PowerShell must rebuild its own module path when an intermediate
process inherited PowerShell 7's path. This helper changes only that child
environment. It neither resolves nor executes a programme or admits a native
fixture result.
"""
from collections.abc import Mapping
from pathlib import PureWindowsPath


def windows_powershell_environment(executable, inherited):
    """Remove only Windows PowerShell's case-insensitive inherited module path."""
    if type(executable) is not str or not executable or '\0' in executable:
        raise ValueError('windows-powershell-executable')
    if not isinstance(inherited, Mapping):
        raise ValueError('windows-powershell-environment')
    result = dict(inherited)
    if any(type(key) is not str or not key or '\0' in key
           or type(value) is not str or '\0' in value
           for key, value in result.items()):
        raise ValueError('windows-powershell-environment')
    # PureWindowsPath treats both separators as path separators on every host.
    # The alias is deliberate: the existing complete fixture uses "powershell".
    if PureWindowsPath(executable).name.casefold() in {'powershell', 'powershell.exe'}:
        result = {key: value for key, value in result.items()
                  if key.casefold() != 'psmodulepath'}
    return result
