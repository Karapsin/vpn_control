"""Fixed host11 whole-envelope codec; existing record, actor and wire limits."""
import base64
import hashlib
import json
import math
import re
import zlib

WIRE_LIMIT = 65536
ROLE_LIMITS = {'dispatch.json':16384,'identity.json':4096,'output/fixture-identity.json':4096,'output/fixture-receipt.json':1048576,'output/handoff.json':1048576,'output/intent.json':8192,'output/lifecycle-receipt.json':1048576,'output/phase-check.json':1048576,'output/probe.json':1048576,'output/run-started.json':1024,'output/worker-finished.json':4096}
ACTOR_COUNT = 2
ACTOR_PASSES = 2
CMDLINE_LIMIT = 16384
# Each record/actor has at most one existing 4KiB identity/stat metadata budget;
# raw record/cmdline bytes have their exact base64 upper bounds, independently.
STRUCTURAL_LIMIT = 4096 * (len(ROLE_LIMITS) + ACTOR_COUNT * ACTOR_PASSES + 1)
DECODED_LIMIT = sum(((limit + 2) // 3) * 4 for limit in ROLE_LIMITS.values()) + ACTOR_COUNT * ACTOR_PASSES * ((CMDLINE_LIMIT + 2) // 3) * 4 + STRUCTURAL_LIMIT
CODEC = 'host11-zlib-base64-json-v1'

def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('wire_duplicate_key')
        result[key] = value
    return result

def _nonfinite(value):
    raise ValueError('wire_nonfinite_number')

def _finite_float(raw):
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("wire_nonfinite_number")
    return value

def _strict_json(raw):
    text = raw.decode('utf-8', 'strict')
    value, end = json.JSONDecoder(object_pairs_hook=_unique, parse_constant=_nonfinite, parse_float=_finite_float).raw_decode(text)
    if end != len(text):
        raise ValueError('wire_json_trailing_bytes')
    return value

def encode_payload(value):
    decoded = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(decoded) > DECODED_LIMIT:
        raise ValueError('wire_decoded_bounds')
    compressed = zlib.compress(decoded, 9)
    wire = json.dumps({'codec': CODEC, 'decodedBytes': len(decoded),
                       'decodedSha256': hashlib.sha256(decoded).hexdigest(),
                       'payload': base64.b64encode(compressed).decode('ascii')},
                      sort_keys=True, separators=(',', ':')).encode('ascii')
    if len(wire) + 1 > WIRE_LIMIT:
        raise ValueError('wire_encoded_bounds')
    return wire

def decode_payload_bytes(wire):
    if type(wire) is not bytes or not 0 < len(wire) <= WIRE_LIMIT:
        raise ValueError('wire_frame_bounds')
    # The producer prints exactly one LF; additional/trailing data is forbidden.
    framed = wire[:-1] if wire.endswith(b'\n') else wire
    envelope = _strict_json(framed)
    if (type(envelope) is not dict or set(envelope) != {'codec', 'decodedBytes', 'decodedSha256', 'payload'}
            or envelope['codec'] != CODEC or type(envelope['decodedBytes']) is not int
            or not 0 <= envelope['decodedBytes'] <= DECODED_LIMIT
            or type(envelope['decodedSha256']) is not str
            or re.fullmatch('[0-9a-f]{64}', envelope['decodedSha256']) is None
            or type(envelope['payload']) is not str):
        raise ValueError('wire_closed_frame_invalid')
    compressed = base64.b64decode(envelope['payload'].encode('ascii'), validate=True)
    if base64.b64encode(compressed).decode('ascii') != envelope['payload']:
        raise ValueError('wire_base64_noncanonical')
    decoder = zlib.decompressobj()
    decoded = decoder.decompress(compressed, DECODED_LIMIT + 1)
    if (len(decoded) > DECODED_LIMIT or not decoder.eof
            or decoder.unused_data or decoder.unconsumed_tail):
        raise ValueError('wire_compressed_bounds_or_trailing')
    if decoder.flush():
        raise ValueError('wire_compressed_unaccounted_bytes')
    if (len(decoded) != envelope['decodedBytes']
            or hashlib.sha256(decoded).hexdigest() != envelope['decodedSha256']):
        raise ValueError('wire_decoded_length_or_hash')
    value = _strict_json(decoded)
    if type(value) is not dict:
        raise ValueError('wire_decoded_shape')
    return decoded

def decode_payload(wire):
    return _strict_json(decode_payload_bytes(wire))


# Pure fixed828 retained-record frame projection; existing codec caps unchanged.
def _retained_record_pin(pin):
    fields={'generation','sha256','bytes','ancestry','hostBootId'}
    if type(pin)is not dict or set(pin)!=fields or type(pin['bytes'])is not int or not 0<pin['bytes']<=4194304:
        raise ValueError('expected_pin_shape')
    if type(pin['sha256'])is not str or re.fullmatch('[0-9a-f]{64}',pin['sha256'])is None or pin['hostBootId']!='25515f23-b966-4c3a-ae63-d38452375578':
        raise ValueError('expected_pin_binding')
    generation=pin['generation'];ancestry=pin['ancestry']
    if type(generation)is not list or len(generation)!=8 or any(type(v)is not int or v<0 for v in generation) or generation[2]!=pin['bytes'] or generation[5:]!=[384,1000,1]:
        raise ValueError('expected_pin_generation')
    if type(ancestry)is not list or not 1<=len(ancestry)<=64 or any(type(row)is not list or len(row)!=4 or any(type(v)is not int or v<0 for v in row)or row[2]&0o170000!=0o040000 for row in ancestry):
        raise ValueError('expected_pin_ancestry')
    return pin

def decode_retained_record_frames(wire, pin):
    LIMIT = 4194304
    CORR = '828431f1-5588-4b99-b85c-1bf1dece9da9'
    _retained_record_pin(pin)
    if type(wire) is not bytes or not 0 < len(wire) <= 8388608:
        raise ValueError('wire_or_record_bound')
    raw = bytearray()
    frames = wire.splitlines(keepends=True)
    if len(frames) != (pin['bytes'] + 1535) // 1536:
        raise ValueError('frame_count')
    for index, frame in enumerate(frames):
        if not 0 < len(frame) <= 4096 or not frame.endswith(b'\n'):
            raise ValueError('frame_bound')
        row = _strict_json(frame[:-1])
        if type(row)is not dict or set(row) != {'state', 'correlationId', 'receiptPin', 'pin', 'replayAllowed', 'sourceClosingAuthenticated', 'kind', 'offset', 'chunk', 'eof'}:
            raise ValueError('frame_fields')
        _retained_record_pin(row['pin'])
        _retained_record_pin(row['receiptPin'])
        if row['state'] != 'record-authenticated' or row['correlationId'] != CORR or row['receiptPin'] != pin or (row['pin'] != pin) or (row['sourceClosingAuthenticated'] is not True) or (row['replayAllowed'] is not False) or (row['kind'] != 'receipt'):
            raise ValueError('frame_binding')
        if type(row['offset']) is not int or row['offset'] != len(raw) or type(row['eof']) is not bool or (row['eof'] != (index == len(frames) - 1)):
            raise ValueError('ordered_offset_or_eof')
        body = base64.b64decode(row['chunk'], validate=True)
        if type(row['chunk']) is not str or base64.b64encode(body).decode() != row['chunk'] or len(body) != min(1536, pin['bytes'] - len(raw)):
            raise ValueError('chunk_bound')
        raw.extend(body)
        if len(raw) > LIMIT:
            raise ValueError('record_bound')
    if len(raw) != pin['bytes'] or hashlib.sha256(raw).hexdigest() != pin['sha256']:
        raise ValueError('final_hash')
    return bytes(raw)
