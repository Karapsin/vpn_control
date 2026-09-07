#!/usr/bin/env python3
"""Build an RPM from the prepared image with verified desktop lifecycle scripts.

The JDK's RPM template registers shortcuts before the old package's unconditional
uninstall script runs. Register after the transaction so existing packages can
upgrade safely, and unregister only when the last installed version is removed.
The remaining metadata and file-list template come from the actual build JDK.
"""
import argparse
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import tempfile
import zipfile

from package_linux_deb import METADATA_OPTIONS as DEB_METADATA_OPTIONS, require


METADATA_OPTIONS = {key: value for key, value in DEB_METADATA_OPTIONS.items() if key != 'maintainer'}
METADATA_OPTIONS['license_type'] = '--linux-rpm-license-type'
DEFAULT_LIFECYCLE = '%post\nDESKTOP_COMMANDS_INSTALL\n\n%preun\nUTILITY_SCRIPTS\nDESKTOP_COMMANDS_UNINSTALL\n'
POSTTRANS = '''set -e
# Register after the old package's scripts, including previously published RPMs.
if [ ! -d /usr/share/desktop-directories ]; then
    mkdir -m 0755 /usr/share/desktop-directories || [ -d /usr/share/desktop-directories ]
fi
DESKTOP_COMMANDS_INSTALL'''
PREUN = '''set -e
UTILITY_SCRIPTS
if [ "$1" -eq 0 ]; then
DESKTOP_COMMANDS_UNINSTALL
fi'''


def desktop_lifecycle_template(template):
    require(template.count(DEFAULT_LIFECYCLE) == 1 and template.count('DESKTOP_COMMANDS_INSTALL') == 1
            and template.count('DESKTOP_COMMANDS_UNINSTALL') == 1,
            'Review changed JDK RPM lifecycle template before packaging')
    return template.replace(DEFAULT_LIFECYCLE, '%posttrans\n' + POSTTRANS + '\n\n%preun\n' + PREUN + '\n')


def package_layout_template(template):
    copy = 'cp -r %{_sourcedir}APPLICATION_DIRECTORY/* %{buildroot}APPLICATION_DIRECTORY\n'
    require(template.count(copy) == 1, 'Review changed JDK RPM application staging before packaging')
    # The prepared image belongs to the builder. Normalize only the new RPM
    # buildroot tree so both restrictive and shared build umasks install the
    # same accessible, non-writable application authority for ordinary users.
    normalized = copy + '''find %{buildroot}APPLICATION_DIRECTORY -type d -exec chmod 0755 '{}' +
find %{buildroot}APPLICATION_DIRECTORY -type f -perm -0100 -exec chmod 0755 '{}' +
find %{buildroot}APPLICATION_DIRECTORY -type f ! -perm -0100 -exec chmod 0644 '{}' +
'''
    return template.replace(copy, normalized)


def jdk_template(java_home):
    with zipfile.ZipFile(java_home / 'jmods/jdk.jpackage.jmod') as module:
        name = 'classes/jdk/jpackage/internal/resources/template.spec'
        entries = [entry for entry in module.infolist() if entry.filename == name]
        require(len(entries) == 1 and entries[0].file_size <= 1024 * 1024, 'Missing or duplicate JDK RPM template')
        return package_layout_template(desktop_lifecycle_template(module.read(entries[0]).decode('utf-8')))


def package_arguments(java_home, image, destination, resources, name, package_name, version, metadata, shortcut=False):
    command = [str(java_home / 'bin/jpackage'), '--type', 'rpm', '--app-image', str(image),
               '--dest', str(destination), '--name', name, '--linux-package-name', package_name,
               '--app-version', version, '--resource-dir', str(resources)]
    for key, option in METADATA_OPTIONS.items():
        value = metadata.get(key)
        if value is not None and str(value):
            command.extend([option, str(value)])
    if shortcut:
        command.append('--linux-shortcut')
    return command


def verify_emitted_scripts(post, posttrans, preun):
    require(post in ('', '(none)'), 'Desktop registration must run after old-package removal')
    prefix = POSTTRANS.split('DESKTOP_COMMANDS_INSTALL')[0]
    require(posttrans.startswith(prefix) and 'xdg-desktop-menu install ' in posttrans[len(prefix):],
            'Generated RPM omitted post-transaction desktop registration')
    guard = '\nif [ "$1" -eq 0 ]; then\n'
    require(preun.startswith('set -e\n') and preun.count(guard) == 1 and preun.rstrip().endswith('\nfi'),
            'Generated RPM omitted final-removal desktop guard')
    guarded = preun.split(guard, 1)[1].rstrip().removesuffix('\nfi')
    require('xdg-desktop-menu uninstall ' in guarded and
            'xdg-desktop-menu uninstall ' not in preun.split(guard, 1)[0],
            'Generated RPM unregisters desktop entries during replacement')
    require('DESKTOP_COMMANDS_' not in posttrans + preun, 'Unexpanded RPM desktop resource')


def verify_package_layout(metadata, launcher_name):
    rows = [line.split('\t') for line in metadata.splitlines()]
    require(rows and all(len(row) == 4 for row in rows), 'Malformed RPM file metadata')
    paths = [row[0] for row in rows]
    require(len(paths) == len(set(paths)), 'Duplicate RPM file paths')
    launchers = [path for path in paths if path.endswith('/bin/' + launcher_name)]
    require(len(launchers) == 1, 'RPM must contain exactly one public launcher')
    application = launchers[0].removesuffix('/bin/' + launcher_name)
    for path, encoded_mode, user, group in rows:
        if path != application and not path.startswith(application + '/'):
            continue
        mode = int(encoded_mode, 8)
        require(user == 'root' and group == 'root', 'RPM application files must have root authority')
        if stat.S_ISDIR(mode):
            valid = stat.S_IMODE(mode) == 0o755
        elif stat.S_ISREG(mode):
            valid = stat.S_IMODE(mode) in (0o644, 0o755)
        else:
            valid = stat.S_ISLNK(mode)
        require(valid, 'RPM application modes are inaccessible or writable by another principal: ' + path)
    launcher = rows[paths.index(launchers[0])]
    require(int(launcher[1], 8) == stat.S_IFREG | 0o755, 'RPM public launcher must remain executable')


def verify_rpm(package, package_name, version, release='1', run_command=subprocess.run, launcher_name=None):
    identity = run_command(['rpm', '-qp', '--qf', '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n', str(package)],
                           check=True, capture_output=True).stdout.decode('utf-8').splitlines()
    expected_arch = {'x86_64': 'x86_64', 'aarch64': 'aarch64', 'arm64': 'aarch64'}.get(platform.machine())
    require(identity == [package_name, version, release, expected_arch],
            'Generated RPM package identity disagrees with the requested native package')
    scripts = []
    for tag in ('POSTIN', 'POSTTRANS', 'PREUN'):
        body = run_command(['rpm', '-qp', '--qf', '%{' + tag + '}', str(package)],
                           check=True, capture_output=True).stdout
        require(len(body) <= 1024 * 1024, 'Unexpectedly large generated RPM scriptlet')
        scripts.append(body.decode('utf-8'))
    verify_emitted_scripts(*scripts)
    files = run_command(['rpm', '-qp', '--qf',
                         '[%{FILENAMES}\t%{FILEMODES:octal}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\n]', str(package)],
                        check=True, capture_output=True).stdout.decode('utf-8')
    verify_package_layout(files, launcher_name or package_name)


def package(java_home, image, destination, name, package_name, version, metadata,
            shortcut=False, run_command=subprocess.run):
    require(platform.system() == 'Linux', 'RPM packages require a native Linux build')
    image = image.resolve(strict=True)
    with (image / 'bin' / name).open('rb') as launcher:
        header = launcher.read(64)
    expected_machine = {'x86_64': 62, 'aarch64': 183, 'arm64': 183}.get(platform.machine())
    require(header[:6] == b'\x7fELF\x02\x01' and expected_machine is not None
            and int.from_bytes(header[18:20], 'little') == expected_machine,
            'Prepared public launcher architecture must match the native build host')
    require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', package_name), 'Noncanonical RPM package name')
    template = jdk_template(java_home)
    require(not destination.is_symlink(), 'Package destination must not be a symlink')
    destination.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='.vpn-rpm-', dir=destination.parent))
    resources = staging / 'resources'
    resources.mkdir()
    (resources / (package_name + '.spec')).write_text(template)
    command = package_arguments(java_home, image, staging, resources, name, package_name, version, metadata, shortcut)
    try:
        run_command(command, check=True)
        artifacts = list(staging.glob('*.rpm'))
        require(len(artifacts) == 1 and artifacts[0].is_file() and not artifacts[0].is_symlink(),
                'Expected exactly one generated RPM')
        artifact = artifacts[0]
        verify_rpm(artifact, package_name, version, str(metadata.get('release') or '1'), run_command, name)
        target = destination / artifact.name
        os.replace(artifact, target)
        shutil.rmtree(staging)
        return target
    except Exception as failure:
        raise RuntimeError('RPM build or verification failed; retained generated evidence at ' + str(staging)) from failure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--java-home', type=Path, required=True)
    parser.add_argument('--app-image', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--name', required=True)
    parser.add_argument('--package-name', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--shortcut', action='store_true')
    for key in METADATA_OPTIONS:
        parser.add_argument('--' + key.replace('_', '-'))
    args = parser.parse_args()
    print(package(args.java_home, args.app_image, args.destination, args.name, args.package_name,
                  args.version, {key: getattr(args, key) for key in METADATA_OPTIONS}, args.shortcut))


if __name__ == '__main__':
    main()
