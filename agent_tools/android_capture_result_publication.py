"""Fixed result evidence publication, with no native or replay authority.

The caller owns ``held`` and closes it in its original finally block. Call
``closing`` after all semantic/body callbacks and immediately before publishing
success. Storage/closing errors must retain the caller's original UNKNOWN.
"""
import hashlib
import re
from pathlib import Path
from agent_tools import android_installer_asset_collection as collection
from agent_tools import android_installer_direct_transport as direct

NAME = 'copy-result.raw'
SINGLE_LIMIT = 1048576


def matches(snapshot, created):
    return (type(created) is dict and set(created) == {'sha256', 'generation'}
            and type(created['sha256']) is str
            and re.fullmatch('[0-9a-f]{64}', created['sha256']) is not None
            and type(created['generation']) is list
            and len(created['generation']) == 9
            and all(type(x) is int for x in created['generation'])
            and created['sha256'] == snapshot['sha256']
            and created['generation'] == snapshot['generation'])


def closing(held, *, source_held, source_custody):
    if not callable(source_custody):
        raise ValueError('result_source_custody_required')
    source_custody()
    # ALL source/result parent reads precede ALL original final leaf checks.
    direct._dispatch_guard([*source_held, *held])


def publish_result(capture, body, *, held, source_held, source_custody):
    """Retain actual create pins and full FD snapshots before caller parsing.

    The returned layout describes evidence only. It never means collection or
    an original native effect completed. No file is overwritten or removed.
    """
    base = collection.collector()  # Authenticates the current full emitter.
    if base['CHUNK'] != 524288 or base['STREAM_LIMIT'] != 201326592:
        raise ValueError('result_archive_shape_changed')
    if type(body) is not bytes or len(body) > base['STREAM_LIMIT']:
        raise ValueError('result_bytes_invalid')
    if type(held) is not list:
        raise ValueError('result_held_population_required')
    closing(held, source_held=source_held, source_custody=source_custody)

    def retain(name, part, created):
        path = Path(capture.path) / name
        actual, pin = direct.snapshot(path, limit=len(part) + 1, private=True)
        if actual != part or not matches(pin, created):
            raise ValueError('result_publication_changed')
        held.append(direct._dispatch_hold(path, pin, part))

    if len(body) <= SINGLE_LIMIT:
        retain(NAME, body, capture.create(NAME, body))
        layout = 'single'
    else:
        created = {}

        def create(name, part):
            if name in created:
                raise ValueError('result_publication_duplicate')
            created[name] = capture.create(name, part)
            return created[name]

        from types import SimpleNamespace
        manifest = base['archive'](SimpleNamespace(create=create), NAME, body)
        if (manifest['bytes'] != len(body)
                or manifest['sha256'] != hashlib.sha256(body).hexdigest()):
            raise ValueError('result_publication_changed')
        offset = 0
        for row in manifest['chunks']:
            part = body[offset:offset + base['CHUNK']]
            offset += len(part)
            if row['pin'] != created[row['name']]:
                raise ValueError('result_publication_changed')
            retain(row['name'], part, created[row['name']])
        if offset != len(body):
            raise ValueError('result_publication_changed')
        name = NAME + '-manifest.json'
        retain(name, base['encoded'](manifest), created[name])
        layout = 'chunks'
    closing(held, source_held=source_held, source_custody=source_custody)
    return {'layout': layout, 'bytes': len(body),
            'sha256': hashlib.sha256(body).hexdigest()}
