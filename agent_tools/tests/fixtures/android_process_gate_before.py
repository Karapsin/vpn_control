# Exact original full idle gate before explicit kernel/console process roles.
def _idle(self, observed, deadline):
    actor, state, current = self._current()
    _need(state == "live" and self._operator_held, "android_owner_unavailable")
    self._native_seed_idle(deadline)
    from . import readiness_adb_jobs
    guest_jobs = readiness_adb_jobs.active_operations(self.root, self.binding.target, self.binding.machine)
    _need(type(guest_jobs) is dict and set(guest_jobs) == {"visibility", "reservations", "runningJobs", "unknownJobs"}
          and guest_jobs["visibility"] is True and all(type(guest_jobs[key]) is list
                for key in ("reservations", "runningJobs", "unknownJobs")), "android_idle_visibility_incomplete")
    _need(not any(guest_jobs[key] for key in ("reservations", "runningJobs", "unknownJobs")), "android_idle_work_active")
    reservations = visual._read_reservations()
    _need(reservations.get(self.reservation_key) == {"memory_mib": self.descriptor["memoryMiB"], "pid": actor["pid"]},
          "android_idle_visibility_incomplete")
    for disk in self.descriptor["writableDisks"]:
        users = subprocess.run(["lsof", "-t", "--", disk["path"]], stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=5, check=False)
        _need(users.returncode == 0 and not users.stderr and users.stdout.decode().split() == [str(actor["pid"])],
              "android_idle_visibility_incomplete")
    for path in self.state_root.glob("effect-*.json"):
        effect = jobs._record(path)
        _need(effect.get("action") in {"start", "resume", "reboot"}, "android_idle_visibility_incomplete")
        if effect["action"] == "reboot":
            _need(effect.get("bootBefore") != observed.boot, "android_idle_work_active")
        elif effect["action"] == "resume":
            _need(observed.guest == "running", "android_idle_work_active")
        elif current is None or effect.get("operationId") != current["operationId"]:
            result = jobs.observe(self.job_root, effect["operationId"], self.host_binding, generation=self.job_generation)
            _need(result["state"] == "terminal", "android_idle_work_active")
    names, _ = self.adb._command(["shell", "ps", "-A", "-o", "NAME"], deadline)
    installers, _ = self.adb._command(["shell", "dumpsys", "package", "installs"], deadline)
    baseline = self.descriptor.get("jobBaseline")
    _need(type(baseline) is list and bool(baseline) and all(type(name) is str for name in baseline),
          "android_idle_visibility_incomplete")
    projected = _process_names(names)
    _need(not (set(projected[1:]) - set(baseline) - {"ps"}), "android_idle_work_active")
    visibility, blockers = providers.android_guest_idle_facts(names, installers)
    _need(not blockers and visibility == frozenset({"installers", "protected_processes"}), "android_idle_work_active")
    # Every durable launch except the current VM owner must be terminal.
    for record in self._launches():
        if current is not None and record == current:
            continue
        result = jobs.observe(self.job_root, record["operationId"], self.host_binding, generation=self.job_generation)
        _need(result["state"] == "terminal", "android_idle_work_active")
    from . import readiness_lease_workflow as leases
    admissions = self.root / ".rag_index" / "readiness-leases" / "admissions"
    if admissions.exists():
        for fixture in admissions.iterdir():
            _need(fixture.is_dir() and not fixture.is_symlink(), "android_idle_visibility_incomplete")
            for path in fixture.glob("*.json"):
                if not re.fullmatch(r"[0-9a-f-]{36}", path.stem):
                    continue
                value = leases.workflow(self.root, "status", {"fixtureId": fixture.name, "operationId": path.stem})
                _need(value.get("state") in {"expired", "cancelled", "restored"} and value.get("restored") is True
                      and value.get("jobState") == "terminal"
                      and (value.get("state")!="restored" or value.get("restorationState")=="terminal"),
                      "android_idle_work_active")
    installed, _ = self.adb._command(["shell", "pm", "list", "packages", "com.kardinal.vpncontrol"], deadline)
    _need(not installed.strip(), "android_idle_work_active")
    return replace(observed, idle_visibility=readiness.IDLE_VISIBILITY, idle_blockers=frozenset())
