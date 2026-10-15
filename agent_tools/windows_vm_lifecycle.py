"""Stop only original, fully reidentified deployment actors; never replay."""


def _actor_absent(row,process,birth):
    import os,select
    def gone():
        try:start=birth(row['pid'])
        except FileNotFoundError:return True
        except ValueError as error:
            if str(error)=='instance_process_dead':return True
            raise
        return start!=row['startTicks']
    if gone():return True
    try:process(row)
    except (FileNotFoundError,ValueError):
        # /proc can become empty/disappear after the first live birth read.
        # Only a second positive death/reuse observation closes that race.
        if gone():return True
        # An exiting Linux task can still report R with an empty cmdline and
        # vanished exe before becoming Z. A pidfd wait proves actual death;
        # a live mismatch still raises after this short bounded observation.
        try:fd=os.pidfd_open(row['pid'],0)
        except ProcessLookupError:
            if gone():return True
            raise
        try:
            if gone():return True
            if select.select([fd],[],[],.25)[0] and gone():return True
        finally:os.close(fd)
        raise
    return gone()


def _closed_instance(spec,context,read,process,birth):
    intent=read('stop-intent.json')
    if (type(intent)is not dict or set(intent)!={'schemaVersion','deploymentId','hostBootId','qemu','swtpm','beforeObservation'}
            or intent['schemaVersion']!=1 or intent['deploymentId']!=spec['deploymentId'] or intent['hostBootId']!=context['hostBootId']):
        raise ValueError('instance_stop_intent')
    for name in ('qemu','swtpm'):
        row=read(name+'-started.json')
        if row!=intent[name]:raise ValueError('instance_stop_actor_changed')
        if not _actor_absent(row,process,birth):raise ValueError('instance_stop_incomplete')
    return {'qemu':{k:intent['qemu'][k] for k in ('pid','startTicks')},
            'swtpm':{k:intent['swtpm'][k] for k in ('pid','startTicks')},
            'positiveAbsence':True,'productReady':False}


def _stop_instance(spec,context,observed,read,process,birth,qmp,save,closing):
    import os,signal,time
    # observed validates the immutable root/spec/setup/boot, process births,
    # executable/argv, disk/firmware holders, asset generations and socket peers.
    before=observed();qemu=read('qemu-started.json');tpm=read('swtpm-started.json')
    process(qemu);process(tpm);closing()
    save('stop-intent.json',{'schemaVersion':1,'deploymentId':spec['deploymentId'],'hostBootId':context['hostBootId'],
                           'qemu':qemu,'swtpm':tpm,'beforeObservation':before})
    def wait(row,seconds):
        deadline=time.monotonic()+seconds
        while not _actor_absent(row,process,birth):
            if time.monotonic()>=deadline:raise ValueError('instance_stop_incomplete')
            time.sleep(.05)
    acknowledged=False
    try:qmp('quit');acknowledged=True
    except (OSError,ValueError):pass
    # A lost quit response is retained as such. Only positive absence closes
    # resources; never send another quit or fall back to a QEMU signal.
    save('stop-quit-observation.json',{'responseClosed':acknowledged})
    wait(qemu,20);closing()
    signalled=False
    if not _actor_absent(tpm,process,birth):
        fd=os.pidfd_open(tpm['pid'],0)
        try:
            process(tpm);closing()
            signal.pidfd_send_signal(fd,signal.SIGTERM,None,0);signalled=True
        finally:os.close(fd)
    wait(tpm,5);closing()
    value=_closed_instance(spec,context,read,process,birth)
    save('stop-result.json',{**value,'quitResponseClosed':acknowledged,'tpmSignalSubmitted':signalled})
    return value
