# Authentic pre-fix method from readiness_android.py; executed only by the causal regression.
def reconcile_ready(self,ready,deadline):
    """Bind only the existing original VM owner after a lost client ACK."""
    _need(self._operator_held,"android_owner_unavailable")
    actor,state,record=self._current()
    _need(state=="live" and actor is not None,"android_owner_unavailable")
    if record is None:
        return  # legacy direct processes gain no durable ownership here
    observed=self.observe(ready.requirements,deadline)
    _need((observed.target,observed.machine,observed.connection,observed.boot,observed.account,observed.session)==ready.identities(),
          "android_input_identity_changed")
    reservation=visual._read_reservations().get(self.reservation_key)
    _need(reservation in ({"memory_mib":self.descriptor["memoryMiB"],"pid":0},
                          {"memory_mib":self.descriptor["memoryMiB"],"pid":actor["pid"]}),"android_idle_visibility_incomplete")
    plans=storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
    with plans._locked():
        plan=plans._read()["plans"].get(self.storage_plan)
    _need(type(plan) is dict and plan.get("directory")==str(self.avd_root)
          and plan.get("state") in {"retained","pending"},"android_idle_visibility_incomplete")
    if reservation["pid"]==actor["pid"] and plan.get("writerPid")==actor["pid"]:
        return
    self._bind_actor(actor)
    _need(self._current()==(actor,state,record),"android_owner_unavailable")
