# Exact original server-selection statement wrapped for isolated execution.
def _original_server(fixture,native_start,server_port):
    return registry.adb_server_identity(server_port)
