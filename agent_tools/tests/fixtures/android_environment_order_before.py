# Exact original generated native program before canonical environment order.
def launch_program(job_root, operation, binding, argv, environment):
    """Snapshot all execution dependencies; no import of a changing checkout."""
    source = ("import sys,types,os,json\nfrom pathlib import Path\n"
              "M=types.ModuleType('android_owner_snapshot');sys.modules[M.__name__]=M\n"
              "exec(compile(" + repr(jobs.owner_source()) + ",'durable-owner-snapshot','exec'),M.__dict__)\n"
              "D=M.__dict__\n"
              "job=Path(" + repr(str(job_root / operation)) + ")\n"
              "binding=D['MachineBinding'].from_dict(" + repr(asdict(binding)) + ")\n"
              "D['_binding_live'](binding)\n"
              "intent=D['_intent'](job," + repr(operation) + ",binding)\n"
              "actor={'pid':os.getpid(),'birth':D['_birth'](os.getpid())}\n"
              "D['_need'](actor['birth'] is not None,'android_owner_generation_unavailable')\n"
              "D['_publish'](job/'emulator.json',{'actor':actor,'operationId':intent['operationId'],"
              "'generation':intent['generation'],'programSha256':intent['programSha256']})\n"
              "argv=" + repr(argv) + "\n"
              "os.execve(argv[0],argv," + repr(environment) + ")\n")
    return jobs.Program("android-existing-instance", source.encode(), stream_limit=1024 * 1024)
