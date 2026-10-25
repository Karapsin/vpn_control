# Exact original initial actor observer before durable seed custody.
def _current(self):
    self.custody_guard()
    records = self._launches()
    if not records:
        actor = self.descriptor["initialActor"]
        actual = jobs._birth(actor["pid"])
        _need(actual in (None, actor["birth"]), "android_owner_unavailable")
        return (actor, "live" if actual else "stopped", None)
    record = records[-1]
    result = jobs.observe(self.job_root, record["operationId"], self.host_binding, generation=self.job_generation)
    if result["state"] == "unsubmitted":
        proof = self._prove_start_unsubmitted(record["recoveryId"])
        return None, "stopped" if proof is not None else "pending", record
    _need(result["state"] in {"running", "terminal", "unknown"}, "android_lifecycle_history_invalid")
    path = self.job_root / record["operationId"] / "emulator.json"
    try:
        receipt = jobs._record(path)
    except jobs.DurableJobError:
        _need(result["state"] == "running", "android_lifecycle_outcome_unknown")
        return None, "pending", record
    intent = jobs._intent(path.parent, record["operationId"], self.host_binding)
    _need(receipt == {"actor": receipt.get("actor"), "operationId": intent["operationId"],
                      "generation": intent["generation"], "programSha256": intent["programSha256"]}
          and record["programSha256"] == intent["programSha256"], "android_lifecycle_history_invalid")
    actor = receipt["actor"]
    _need(type(actor) is dict and set(actor) == {"pid", "birth"} and type(actor["pid"]) is int
          and actor["pid"] > 0 and type(actor["birth"]) is str, "android_owner_unavailable")
    actual = jobs._birth(actor["pid"])
    _need(actual in (None, actor["birth"]), "android_owner_unavailable")
    if actual:
        _need(result["state"] == "running", "android_lifecycle_outcome_unknown")
        return actor, "live", record
    if result["state"] == "terminal":
        return actor, "stopped", record
    return actor, "pending", record
