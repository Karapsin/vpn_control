"""Bounded read-only QMP protocol component; caller owns native admission."""
import json
import os
import re
import time


def parse_channel_admission(arguments):
    """Only public fixed channel identity may vary at the native entry."""
    if (type(arguments) not in (list, tuple) or len(arguments) != 2 or
            type(arguments[0]) is not str or type(arguments[1]) is not str or
            re.fullmatch('[0-9a-f]{32}', arguments[0]) is None or
            re.fullmatch('[0-9a-f]{64}', arguments[1]) is None):
        raise ValueError('tertiary-channel-admission-input')
    return {'correlationId': arguments[0], 'receiptSha256': arguments[1]}


def verify_channel_admission(metadata, admission):
    if type(admission) is not dict or set(admission) != {'correlationId', 'receiptSha256'}:
        raise ValueError('tertiary-channel-admission-input')
    expected = parse_channel_admission([
        admission.get('correlationId'), admission.get('receiptSha256')])
    if (type(metadata) is not dict or
            any(metadata.get(key) != value for key, value in expected.items())):
        raise ValueError('tertiary-current-channel-receipt')
    return expected


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('terminal-observe-qmp-duplicate-key')
        result[key] = value
    return result


def read_frame(sock):
    data = bytearray()
    stop = time.monotonic() + 10
    for _ in range(16384):
        if time.monotonic() >= stop:
            raise ValueError('terminal-observe-qmp-deadline')
        chunk = sock.recv(1)
        if not chunk:
            raise ValueError('terminal-observe-qmp-eof')
        data.extend(chunk)
        if chunk == b'\n':
            return json.loads(data, object_pairs_hook=unique_object)
    raise ValueError('terminal-observe-qmp-bound')


def query_status(sock, correlation):
    """Caller supplies an already admitted socket with a finite timeout."""
    greeting = read_frame(sock)
    if type(greeting) is not dict or 'QMP' not in greeting:
        raise ValueError('terminal-observe-qmp-greeting')
    results = []
    for command in ('qmp_capabilities', 'query-status'):
        request_id = 'tertiary-' + correlation + '-' + command
        sock.sendall((json.dumps({'execute': command, 'id': request_id}) + '\n').encode())
        response = None
        for _ in range(8):
            candidate = read_frame(sock)
            if type(candidate) is not dict:
                raise ValueError('terminal-observe-qmp-reply-type')
            if 'event' in candidate:
                if (type(candidate['event']) is not str or
                        any(key in candidate for key in ('return', 'error', 'id'))):
                    raise ValueError('terminal-observe-qmp-event')
                continue
            response = candidate
            break
        if (type(response) is not dict or set(response) != {'return', 'id'} or
                response['id'] != request_id):
            raise ValueError('terminal-observe-qmp-reply')
        results.append(response['return'])
    status = results[1]
    if (type(status) is not dict or type(status.get('status')) is not str or
            len(status['status']) > 128 or type(status.get('running')) is not bool or
            type(status.get('singlestep')) is not bool):
        raise ValueError('terminal-observe-status-types')
    return status


def close_observation(sock, journal_fd):
    """Always attempt both owned descriptor closes, including socket failures."""
    try:
        if sock is not None:
            sock.close()
    finally:
        if journal_fd is not None:
            os.close(journal_fd)
