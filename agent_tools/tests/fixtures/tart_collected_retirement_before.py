# Exact original guest_jobs getter, before collected-owner retirement.
def guest_jobs(self):
    """Original private packets only; guest status is derived by the probe.

    Missing local records cannot hide foreign guest roots because the fixed
    probe independently enumerates the guest namespace before idle proof.
    """
    self._pins()
    directory = self.lifecycle_root / "guest-programs"
    if not directory.exists():
        _need(not directory.is_symlink(), "tart_guest_packet_invalid")
        return []
    jobs._private(directory, directory=True)
    result = []
    for path in sorted(directory.iterdir()):
        _need(len(result) < 1000 and path.name.endswith(".json"), "tart_guest_packet_invalid")
        value = jobs._record(path)
        _need(set(value) == {"packet", "admissionPath", "admissionPin"}, "tart_guest_packet_invalid")
        original_path = registry._under(value["admissionPath"], self.root / ".runtime")
        original, pin = registry._json(original_path)
        packet = _guest_packet(value["packet"], self.binding)
        _need(path.name == packet["operationId"] + ".json" and pin == value["admissionPin"]
              and original.get("packet") == packet and original.get("operationId") == packet["operationId"]
              and original.get("provider") == self.descriptor["provider"], "tart_guest_packet_changed")
        result.append(packet)
    return result
