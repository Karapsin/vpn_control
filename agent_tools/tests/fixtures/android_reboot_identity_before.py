# Authentic pre-fix method from readiness_android.py.
def _recover(self, action, recovery_identity, observed, deadline):
    _need(action in self.capabilities and re.fullmatch(r"[0-9a-f]{64}", recovery_identity), "provider_recovery_unqualified")
    if action == "reconnect":
        _need(observed.target == self.binding.target and observed.machine == self.binding.machine,
              "android_input_identity_changed")
        return self.transport.recover(recovery_identity, observed.connection, deadline)
    current = self.observe(readiness.Requirements(frozenset({"interactive_desktop"})), deadline)
    _need(all(getattr(current, key) == getattr(observed, key)
              for key in ("target", "machine", "connection", "boot", "account", "session")),
          "android_input_identity_changed")
    if action == "wake_display":
        return self.adb.recover(action, recovery_identity, observed, deadline)
    effect = self.state_root / ("effect-" + recovery_identity + ".json")
    if effect.exists() and not (action == "start" and self._retry_start):
        return  # lost ACK observes the original, never sends power again
    if action == "start":
        _need(current.guest == "stopped", "android_input_state_changed")
        self._stopped_disk_guard()
        plans = storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
        plans.settle(self.storage_plan)
        plans.check("android", "start", self.avd_root, current_fixture_id=self.storage_plan)
        # A zero-PID reservation can only be released when its signed prior
        # generation is proven terminal and every original VM actor is gone.
        reservation = visual._read_reservations().get(self.reservation_key)
        if reservation == {"memory_mib": self.descriptor["memoryMiB"], "pid": 0}:
            _need(self._current()[1] == "stopped" and bool(self._launches()), "android_idle_visibility_incomplete")
            visual._release_visual_reservation(self.reservation_key)
        memory = local_fixture_admission.memory_plan(self.descriptor["memoryMiB"], deadline)
        jobs._publish(self.state_root / ("admission-" + recovery_identity + "-attempt-" + str(self._dispatch_attempt) + ".json"), memory)
        if self.reservation_key=="android":
            visual._admit_visual_start("android", self.descriptor["memoryMiB"], storage_fixture_id=self.storage_plan)
        else:
            visual._admit_recovery_fixture_start("android-emulator",self.reservation_digest,
                self.descriptor["memoryMiB"],storage_fixture_id=self.storage_plan)
        operation = str(uuid5(NAMESPACE_URL, "android-existing-instance:" + recovery_identity))
        program = launch_program(self.job_root, operation, self.host_binding,
                                 self.descriptor["argv"], self.descriptor["environment"])
        launches = self._launches()
        originals = [record for record in launches if record["recoveryId"] == recovery_identity]
        _need(len(originals) <= 1, "android_lifecycle_history_invalid")
        index = originals[0]["index"] if originals else len(launches)
        record = {"index": index, "operationId": operation,
                  "recoveryId": recovery_identity, "programSha256": program.digest}
        if originals:
            _need(originals[0] == record and self._retry_start, "android_lifecycle_history_invalid")
        expected_effect = {"action": action, "recoveryId": recovery_identity, "operationId": operation}
        if effect.exists():
            _need(jobs._record(effect) == expected_effect and self._retry_start, "android_lifecycle_history_invalid")
        else:
            jobs._publish(effect, expected_effect)
        if not originals:
            jobs._publish(self.state_root / f"launch-{index:06d}.json", record)
        jobs.submit(self.job_root, operation, self.host_binding, program, generation=self.job_generation)
        end = min(deadline, self.clock() + 5)
        while self.clock() < end:
            try:
                actor, state, _ = self._current()
            except providers.ProviderError as error:
                if str(error) != "android_lifecycle_outcome_unknown":
                    raise
                time.sleep(min(.02, max(0, end-self.clock())))
                continue
            if actor is not None and state == "live":
                self._bind_actor(actor)
                return
            time.sleep(.02)
        return
    actor, state, _ = self._current()
    _need(state == "live", "android_owner_unavailable")
    if action == "resume":
        _need(current.guest in {"paused", "suspended"}, "android_input_state_changed")
        tail = ["emu", "avd", "resume"]
    elif action == "reboot":
        self._bind_actor(actor)
        self._idle(current, deadline)
        _need(current.guest == "running", "android_input_state_changed")
        tail = ["reboot"]
    else:
        raise providers.ProviderError("provider_recovery_unqualified")
    jobs._publish(effect, {"action": action, "recoveryId": recovery_identity, "bootBefore": current.boot, "actor": actor})
    self.adb._command(tail, deadline)
