"""Fixed original-owner IOPM assertion observer, never an effect API.

Apple IOPMLib.h declares IOPMCopyAssertionsByProcess's CFNumberPID/array shape;
IOKitUser/pwr_mgt.subproj/IOPMLibPrivate.h defines AssertionId and AssertPID.
32-bit assertion handles are process-local; foreign CopyProperties is no proof.
Importing this module does not open a framework or perform native observation.
"""
def verify_owned_assertions(api, owner, expected, birth):
    """Read-only positive proof for one ORIGINAL active lease owner.

    owner and expected come from authenticated original lease-acquired receipt.
    Caller must never derive owner identity or assertion IDs from a fresh job.
    This function performs no create/release/settings/power/session action.
    """
    import ctypes as C
    def need(value):
        if not value:raise ValueError('original_assertion_inventory_unverified')
    need(type(owner)is dict and set(owner)=={'pid','birth'} and type(owner['pid'])is int
         and owner['pid']>0 and type(owner['birth'])is str and owner['birth']
         and type(expected)is dict and len(expected)==2
         and set(expected.values())=={'PreventUserIdleSystemSleep','PreventUserIdleDisplaySleep'}
         and all(type(key)is int and 0<key<2**32 for key in expected))
    api.validate_identity();need(birth(owner['pid'])==owner['birth'])
    cf,io=api.cf,api.io
    def fn(name,result,args):
        value=getattr(cf,name);value.restype=result;value.argtypes=args
        return value
    get=fn('CFArrayGetValueAtIndex',C.c_void_p,[C.c_void_p,C.c_long])
    dictionary_type=fn('CFDictionaryGetTypeID',C.c_ulong,[])
    retain=fn('CFRetain',C.c_void_p,[C.c_void_p])
    dictionary=C.c_void_p();need(io.IOPMCopyAssertionsByProcess(C.byref(dictionary))==0 and dictionary.value)
    try:
        count=cf.CFDictionaryGetCount(dictionary);need(0<=count<=65536)
        keys=(C.c_void_p*count)();values=(C.c_void_p*count)()
        cf.CFDictionaryGetKeysAndValues(dictionary,keys,values)
        seen=set();found={}
        for key,value in zip(keys,values):
            pid=C.c_int64()
            need(cf.CFGetTypeID(key)==cf.CFNumberGetTypeID()
                 and cf.CFNumberGetValue(key,4,C.byref(pid)) and 0<pid.value<2**31
                 and pid.value not in seen and cf.CFGetTypeID(value)==cf.CFArrayGetTypeID())
            seen.add(pid.value)
            size=cf.CFArrayGetCount(value);need(0<=size<=65536)
            if pid.value!=owner['pid']:continue
            need(size==len(expected))
            for index in range(size):
                row=get(value,index);need(row and cf.CFGetTypeID(row)==dictionary_type())
                props=api.native.value(retain(row));need(type(props)is dict)
                identity=props.get('AssertionId');kind=props.get('AssertType')
                need(type(identity)is int and identity in expected and identity not in found
                     and kind==expected[identity] and type(props.get('AssertPID'))is int
                     and props['AssertPID']==owner['pid'] and type(props.get('AssertLevel'))is int
                     and props['AssertLevel']==255 and props.get('AssertName')=='VPNControlTemporaryGUILease'
                     and props.get('TimeoutAction')=='TimeoutActionRelease'
                     and type(props.get('TimeoutSeconds'))in (int,float) and 0<props['TimeoutSeconds']<=18000)
                found[identity]=kind
        need(found==expected and birth(owner['pid'])==owner['birth']);api.validate_identity()
        return {'owner':owner,'assertions':sorted(found),'active':True,'nativeInventoryComplete':True}
    finally:cf.CFRelease(dictionary)
