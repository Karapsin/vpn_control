# Exact serializer-only AST from preserved original host11 beforeimage8dfaa63f.
encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
if len(encoded) > 65536:
    result = {'state': 'unknown', 'reason': 'aggregate_capture_bounds', 'correlationId': CORRELATION, 'replayAllowed': False, 'leaseReleased': False, 'recordsAuthenticated': True, 'completeCaptureRetained': False, 'encodedBytes': len(encoded)}
print(json.dumps(result, sort_keys=True, separators=(',', ':')), flush=True)
