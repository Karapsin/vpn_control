"""The VM-host job of one complete in-guest ``:desktopApp:test`` (windows_desktop_test).

windows_desktop_test renders this file after windows_scenario_host_job into one program that the
durable owner runs on the VM host, so it reuses that job's QGA journals, fence, context, publisher,
ordinary-user task and evidence stages unchanged. Imported as a module (tests), it takes the same
names from windows_scenario_host_job.

Differences from a scenario row, all closed here:
- the six admitted archives (source, JDK, Gradle, dependency repository, CI's .NET SDK and the
  offline NuGet seed) are pushed as pinned publisher endpoints, in larger QGA chunks, after a
  read-only free-space check and after the Python tree the worker needs is listed and bounded;
- the worker runs the pinned in-guest runner (windows_desktop_test_guest) through its existing
  ``qualification`` action, with the one argv built here;
- after the task, the runner's summary and results zip are read back and kept beside the receipt;
- the pushed archives are deleted by one identity-checked SYSTEM program once the exit is known and
  nothing can hold them: after the owner exited, or after a known failure before any task launched.
A failing test is data in the receipt; job exit 1 names a tool stage.
"""
if globals().get("__package__"):  # Imported as a module; the rendered program already defines these names.
    from .windows_scenario_host_job import (  # noqa: F401
        EXIT_FAILED, EXIT_PASSED, EXIT_REFUSED, EXIT_UNKNOWN, FILE_PIN_LIMIT, DIRECTORY_PIN_LIMIT, KNOWN_EXITS,
        POWERSHELL_PATH, PYTHON_REQUIRED, RECEIPT_BYTES, Job, KnownFailure, Refused, Unknown,
        assert_closed, assert_closed_worker, bootstrap_inputs, bound_input, build_receipt, decode_stdout,
        refused_before_effects, token, wrap_output, _sha, _unique)

import hashlib as _desktop_hashlib
import json as _desktop_json
import os as _desktop_os
import re as _desktop_re

DESKTOP_SCENARIO = "windows-desktop-test"
ARCHIVE_ROLES = ("source", "jdk", "gradle", "dependencies", "dotnet", "nuget")
# The proven route writes 32,768 bytes per guest-file-write; the archives are one to one and a half gigabytes,
# so they use four times that. A QGA reply limit there would end the job at publish as guest_file_push_lost.
ARCHIVE_CHUNK_BYTES = 131072
SUMMARY_READ_LIMIT = 1024 * 1024
PROGRESS_READ_LIMIT = 4096
PROGRESS_POLLS = 12  # One progress read per minute of five-second status polls.
DESKTOP_RECEIPT_STAGES = frozenset({"anchor", "context", "publish", "requests", "run", "results", "evidence", "cleanup", "receipt"})
_DESKTOP_CODE = _desktop_re.compile(r"[A-Za-z0-9_.:-]{1,120}\Z")
_DESKTOP_SHA = _desktop_re.compile(r"[0-9a-f]{64}\Z")
_DRIVE = _desktop_re.compile(r"[A-Z]:\\")

# Read-only: the profile drive's free space before anything is published.
DISK_TEMPLATE = r"""$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
@@INPUT@@
if([string]$m.drive -cnotmatch '\A[A-Z]\z'){throw 'DESKTOP_DISK_DRIVE'}
$drive=[IO.DriveInfo]::new([string]$m.drive)
$r=[ordered]@{schemaVersion=1;state='desktop-test-disk-observed';operationId=$m.operationId;drive=[string]$m.drive;freeBytes=[long]$drive.AvailableFreeSpace;totalBytes=[long]$drive.TotalSize;productOperation=$false}
[Console]::WriteLine(($r|ConvertTo-Json -Depth 8 -Compress))
"""

# One exclusive DELETE handle per pushed archive, opened without following a reparse point; its volume,
# file index and size must be the published pin's before the delete disposition is set on that handle. An
# archive whose push or verification never completed has only its endpoint's volume and file index: sizeKnown false.
CLEANUP_TEMPLATE = r"""$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
@@INPUT@@
Add-Type -TypeDefinition @'
using System;using System.ComponentModel;using System.Runtime.InteropServices;using Microsoft.Win32.SafeHandles;
public static class VpnDesktopTestCleanup {
 [StructLayout(LayoutKind.Sequential)]struct Info { public uint Attributes,CreationLow,CreationHigh,AccessLow,AccessHigh,WriteLow,WriteHigh,Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info result);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetFileInformationByHandle(SafeFileHandle handle,int kind,ref byte value,uint size);
 public static string Delete(string path,uint volume,ulong index,ulong size,bool sizeKnown){
  SafeFileHandle h=CreateFile(path,0x10080,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
  if(h.IsInvalid){int error=Marshal.GetLastWin32Error();h.Dispose();if(error==2||error==3)return "absent";if(error==32)return "held";throw new Win32Exception(error);}
  using(h){
   Info r;if(!GetFileInformationByHandle(h,out r))throw new Win32Exception(Marshal.GetLastWin32Error());
   if((r.Attributes&0x410)!=0||r.Links!=1)return "not-the-published-file";
   if(r.Volume!=volume||((((ulong)r.IndexHigh)<<32)|r.IndexLow)!=index||(sizeKnown&&((((ulong)r.SizeHigh)<<32)|r.SizeLow)!=size))return "not-the-published-file";
   byte delete=1;if(!SetFileInformationByHandle(h,4,ref delete,1))throw new Win32Exception(Marshal.GetLastWin32Error());
  }
  return "deleted";
 }
}
'@ -ReferencedAssemblies @('System','System.Core')
$rows=[Collections.Generic.List[object]]::new()
foreach($target in @($m.targets)){
 $path=[string]$target.path
 if(-not $path.StartsWith(([string]$m.workspace)+'\',[StringComparison]::Ordinal) -or $path.Substring(([string]$m.workspace).Length+1) -cnotmatch '\Adesktop-test-[a-z]+\.zip\z'){throw 'DESKTOP_CLEAN_TARGET'}
 if($target.sizeKnown -isnot [bool]){throw 'DESKTOP_CLEAN_SIZE_KNOWN'}
 $state=[VpnDesktopTestCleanup]::Delete($path,[uint32]$target.volumeSerial,[uint64]$target.fileIndex,[uint64]$target.sizeBytes,[bool]$target.sizeKnown)
 $rows.Add([ordered]@{path=$path;state=$state})
}
$r=[ordered]@{schemaVersion=1;state='desktop-test-archives-cleaned';operationId=$m.operationId;targets=@($rows.ToArray());freeBytes=[long]([IO.DriveInfo]::new([string]$m.drive)).AvailableFreeSpace;productOperation=$false}
[Console]::WriteLine(($r|ConvertTo-Json -Depth 8 -Compress))
"""


def desktop_summary(raw, plan, guest):
    """The runner's summary, closed to what this job reports; anything else is a known failure."""
    try:
        value = _desktop_json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeDecodeError, ValueError):
        raise KnownFailure("desktop_runner_summary_invalid") from None
    desktop = plan["desktopTest"]
    fields = {"schema", "schemaVersion", "operationId", "sourceCommit", "outcome", "failedStage", "failure", "stages", "gradle",
              "results", "jdkRelease", "dotnet", "nuget", "archives", "freeBytesBefore", "freeBytesAfter", "productProcessesBefore",
              "productProcessesAfter", "productState", "userToolState", "profileEntries", "seconds", "workRoot"}
    stages = {*guest.STAGES, "cleanup"}
    results, gradle, work = value.get("results"), value.get("gradle"), value.get("workRoot")
    valid = (type(value) is dict and set(value) == fields and value["schema"] == guest.SUMMARY_SCHEMA and value["schemaVersion"] == 1
             and value["operationId"] == plan["operationId"] and value["sourceCommit"] == desktop["sourceCommit"]
             and value["outcome"] in ("completed", "failed")
             and (value["failedStage"] is None) == (value["failure"] is None) == (value["outcome"] == "completed")
             and (value["failedStage"] is None or value["failedStage"] in stages)
             and (value["failure"] is None or type(value["failure"]) is str and _DESKTOP_CODE.fullmatch(value["failure"]) is not None)
             and type(value["stages"]) is list and len(value["stages"]) <= len(stages)
             and all(type(row) is dict and row.get("name") in stages for row in value["stages"])
             and type(work) is dict and type(work.get("created")) is bool and type(work.get("deleted")) is bool
             and (results is None or type(results) is dict and results.get("name") == guest.RESULTS_LEAF
                  and type(results.get("bytes")) is int and 0 < results["bytes"] <= guest.RESULTS_ZIP_LIMIT
                  and type(results.get("sha256")) is str and _DESKTOP_SHA.fullmatch(results["sha256"]) is not None
                  and type(results.get("xmlFiles")) is int)
             and (gradle is None or type(gradle) is dict and (gradle.get("exitCode") is None or type(gradle["exitCode"]) is int)
                  and type(gradle.get("deadline")) is bool))
    if not valid:
        raise KnownFailure("desktop_runner_summary_invalid")
    return value


class DesktopTestJob(Job):
    """One desktop test operation on one VM. ``rt`` is the same seam as the scenario job's."""

    def __init__(self, rt, plan, files):
        super().__init__(rt, plan, files)
        self.desktop = plan["desktopTest"]
        self.runner_pin = self.runner = self.results = self.disk = self.summary_record = None
        self.cleanup = {"state": "not-started"}
        self.status_polls = 0
        self.archive_endpoints = {}  # role -> the identity of the endpoint the publisher created for that archive

    def guest(self):
        return self._load("windows_desktop_test_guest")

    # Archives: staged on this host before submit, hashed here again while pushed, and in the guest.
    def staged(self):
        return [self.plan["packages"][role] for role in ARCHIVE_ROLES]

    def package(self):
        return None

    def _chunks(self, source):
        if type(source) is bytes:
            yield from super()._chunks(source)
            return
        descriptor = self._artifact(source)
        digest, total = _desktop_hashlib.sha256(), 0
        try:
            while True:
                part = _desktop_os.read(descriptor, ARCHIVE_CHUNK_BYTES)
                if not part:
                    break
                digest.update(part)
                total += len(part)
                yield part
        finally:
            _desktop_os.close(descriptor)
        if total != source["bytes"] or digest.hexdigest() != source["sha256"]:
            raise ValueError("artifact_cache_changed")

    def stage_context(self):
        super().stage_context()
        guest = self.guest()
        for role in ARCHIVE_ROLES:
            self.paths["file:" + role] = self.workspace + "\\" + guest.ARCHIVE_LEAVES[role]
        self.paths.update(runnerRequest=self.operation_root + "\\" + guest.REQUEST_LEAF,
                          runnerSummary=self.operation_root + "\\" + guest.SUMMARY_LEAF,
                          runnerResults=self.operation_root + "\\" + guest.RESULTS_LEAF,
                          runnerProgress=self.operation_root + "\\" + guest.PROGRESS_LEAF)

    def _desktop_program(self, label, template, m, decide):
        """A read-only or own-file SYSTEM program bound to this boot; ``decide`` validates its closed reply.

        Its terminal is saved before this decodes it, so a reply that does not decode is a known failure
        (ValueError here); a lost acknowledgement or terminal stays the base job's Unknown.
        """
        emitter = self._load("windows_artifact_transfer")

        def render():
            return wrap_output(emitter._boot_bound(template.replace("@@INPUT@@", bound_input(m), 1), self.raw_context))
        terminal, pid = self.guest_program(label, self._rendered(render))
        if refused_before_effects(terminal):
            raise KnownFailure("desktop_program_refused:" + label)
        try:
            value = emitter.decode_guest_result({"transport": "inline"}, decode_stdout(terminal), self.raw_context, pid)
            if type(value) is not dict or value.get("operationId") != self.op or value.get("productOperation") is not False:
                raise ValueError("desktop_program_identity")
            return decide(value)
        except (ValueError, TypeError, KeyError, AttributeError):
            raise ValueError("desktop_program_reply:" + label) from None

    def _drive(self):
        profile = self.context["profileRoot"]
        if _DRIVE.match(profile) is None:
            raise KnownFailure("desktop_profile_drive")
        return profile[0]

    def _disk_space(self):
        needed = sum(self.plan["packages"][role]["bytes"] for role in ARCHIVE_ROLES) + self.desktop["minimumFreeBytes"]

        def decide(value):
            if value.get("state") != "desktop-test-disk-observed" or type(value.get("freeBytes")) is not int:
                raise ValueError("desktop_disk_reply")
            return value["freeBytes"]
        try:
            free = self._desktop_program("desktop-disk-space", DISK_TEMPLATE,
                                         {"schemaVersion": 1, "action": "desktop-disk", "operationId": self.op, "drive": self._drive()},
                                         decide)
        except ValueError:
            raise KnownFailure("desktop_disk_unreadable") from None
        self.disk = {"freeBytes": free, "neededBytes": needed}
        if free < needed:
            raise KnownFailure("desktop_disk_space_insufficient")

    def stage_publish(self):
        self._disk_space()
        read_paths = list(self.row["readPins"])
        self._initialize(read_paths)
        # Read-only and before any byte of the archives is pushed: a fixture without the scenario Python, or a tree
        # past the pin bound, refuses with nothing to delete.
        python = self._listed("python", self.paths["python"], PYTHON_REQUIRED)
        files, directories = self._tree_paths(self.paths["python"], python)
        # The worker request holds every pin of the run: read pins, its sources, the archives, the runner request, the tree.
        if (len(read_paths) + 2 + len(ARCHIVE_ROLES) + 1 + len(files) > FILE_PIN_LIMIT
                or len(self.directory_pins) + len(directories) > DIRECTORY_PIN_LIMIT):
            raise KnownFailure("worker_pin_bound")
        targets = []
        for relative, role, kind in self.row["guestFiles"]:
            raw = self.files[relative]
            targets.append({"role": role, "path": self.paths["file:" + role], "bytes": len(raw), "sha256": _sha(raw),
                            "kind": kind, "raw": raw})
        for role in ARCHIVE_ROLES:
            package = self.plan["packages"][role]
            targets.append({"role": role, "path": self.paths["file:" + role], "bytes": package["bytes"],
                            "sha256": package["sha256"], "kind": "data", "raw": package})
        self.file_pins = self._publish_files(targets, "publish")
        self.read_pins = self._read_pins(read_paths)
        self.python_tree = self._tree("python", self.paths["python"], "python-runtime", python)

    def _publisher(self, label, action, *, unknown=None, **fields):
        """The base publisher; an archive endpoint's identity is kept as it is created, so a push or verification
        that fails afterwards still leaves each archive deletable by identity."""
        value, required = super()._publisher(label, action, unknown=unknown, **fields)
        if action == "endpoints":
            self._note_archive_endpoints(fields.get("targets"), value.get("endpoints"))
        return value, required

    def _note_archive_endpoints(self, rows, created):
        if type(rows) is not list or type(created) is not list or len(rows) != len(created):
            return
        for row, receipt in zip(rows, created):
            role = row.get("role") if type(row) is dict else None
            if role not in ARCHIVE_ROLES or role in self.archive_endpoints:
                continue
            pin = receipt.get("filePin") if type(receipt) is dict else None
            identity = pin.get("nativeIdentity") if type(pin) is dict else None
            if (type(identity) is dict and pin.get("path") == row.get("path") == self.paths["file:" + role]
                    and type(identity.get("volumeSerial")) is int and type(identity.get("fileIndex")) is int):
                self.archive_endpoints[role] = {"path": pin["path"], "volumeSerial": identity["volumeSerial"],
                                                "fileIndex": identity["fileIndex"]}

    def runner_request(self):
        guest = self.guest()
        profile = self.context["profileRoot"]
        request = {"schema": guest.REQUEST_SCHEMA, "schemaVersion": 1, "operationId": self.op,
                   "sourceCommit": self.desktop["sourceCommit"], "profileRoot": profile, "operationRoot": self.operation_root,
                   "workspace": self.workspace, "workRoot": profile + "\\" + guest.WORK_PREFIX + self.op[:8],
                   "archives": {role: {"path": self.paths["file:" + role], "sha256": self.plan["packages"][role]["sha256"],
                                       "bytes": self.plan["packages"][role]["bytes"]} for role in ARCHIVE_ROLES},
                   "jdk": dict(self.desktop["jdk"]), "gradle": dict(self.desktop["gradle"]), "dotnet": dict(self.desktop["dotnet"]),
                   "nuget": {"packages": [dict(row) for row in self.desktop["nuget"]["packages"]]},
                   "gradleDeadlineSeconds": self.desktop["gradleDeadlineSeconds"], "minimumFreeBytes": self.desktop["minimumFreeBytes"]}
        try:
            guest.validate_request(request, windows=True)  # The validator the guest itself runs.
        except guest.StageFailure as failure:
            raise KnownFailure("desktop_runner_request:" + failure.code) from None
        return request

    def _build_requests(self):
        planner = self._load("windows_ordinary_task")
        row, paths, owner = self.row, self.paths, self.file_pins["owner"]
        limit = row["rawStreamLimitBytes"]
        self.runner_pin = self._publish_request("runner-request", paths["runnerRequest"], self.runner_request())
        runtime = self._python_runtime()
        python = self.python_tree
        expected = {"operationId": self.op, "operationRoot": self.operation_root, "context": self.context, "owner": owner["path"],
                    "ownerSha256": owner["sha256"], "bootstrapTrees": [python["tree"]], "pythonRuntime": runtime, "worker": None,
                    "installedRoot": paths["installed"]}
        # The worker admits its request only if that request pins its interpreter and its own source
        # (windows_ordinary_process_owner.Owner: owner-interpreter-source-pins), as the scenario rows' module pins do.
        worker_files = [*self.read_pins, *python["filePins"], self.file_pins["worker"], self.file_pins["runner"],
                        *(self.file_pins[role] for role in ARCHIVE_ROLES), self.runner_pin]
        worker_directories = [*self.directory_pins, *python["directoryPins"]]
        # The one argv: the admitted interpreter, isolated, the pinned runner and its pinned request.
        closed = {"qualificationArgv": [paths["pythonExe"], "-I", "-S", "-B", paths["file:runner"], "--request",
                                        paths["runnerRequest"], "--request-sha256", self.runner_pin["sha256"]],
                  "expectedExitCode": 0}
        worker_common = planner.common_request(self.context, self.op, self.operation_root, worker_files, worker_directories,
                                               [python["tree"]], limit, runtime)
        requests = {"worker": planner.worker_request(worker_common, row["workerAction"], **closed)}
        expected["worker"] = {"inputs": closed, "files": {pin["path"]: pin["sha256"] for pin in worker_files},
                              "directories": [pin["path"] for pin in worker_directories], "trees": [python["tree"]]}
        assert_closed_worker(row, requests["worker"], expected)
        self.worker = self._publish_request("worker-request", paths["workerRequest"], requests["worker"])
        bootstrap_files = [*(pin for pin in self.read_pins if pin["path"] == POWERSHELL_PATH), owner, *python["filePins"],
                           self.file_pins["worker"], self.worker]
        bootstrap_directories = [*self.directory_pins, *python["directoryPins"]]
        inputs = bootstrap_inputs(row, paths, worker_pin=self.worker, encode=planner.data)
        common = planner.common_request(self.context, self.op, self.operation_root, bootstrap_files, bootstrap_directories,
                                        [python["tree"]], limit, runtime)
        requests["bootstrap"] = planner.bootstrap_request(common, row["bootstrapMode"], **{k: v for k, v in inputs.items() if k != "mode"})
        expected.update(files={pin["path"]: pin["sha256"] for pin in bootstrap_files},
                        directories=[pin["path"] for pin in bootstrap_directories], bootstrap=inputs)
        assert_closed(row, requests, expected)
        self.request_pin = self._publish_request("bootstrap-request", paths["bootstrapRequest"], requests["bootstrap"])
        self.rendered_task = planner.render_task(requests["bootstrap"], owner, self.request_pin)
        assert_closed(row, {**requests, "task": self.rendered_task}, {**expected, "requestSha256": self.request_pin["sha256"]})

    def _check_task(self, value):
        """The worker exits 0 when its runner completed and 1 otherwise; the runner's summary says which stage."""
        def need(condition, code):
            if not condition:
                raise KnownFailure("task_" + code)
        kinds = [row.get("kind") for row in value.get("events", [])]
        if kinds and "terminal" not in kinds and "refused-before-native-start" not in kinds:
            raise Unknown("task_child_outcome_unknown")
        need(value.get("taskDeleted") is True, "not_deleted")
        need(value.get("ownerExitCode") in (0, 1) and value.get("terminalExitCode") == value.get("ownerExitCode"), "exit_code")
        need(len(kinds) >= 3 and kinds[0] == "submission-intent" and kinds[-1] == "terminal", "events")
        need(value.get("commandLineMatched") is True, "command_line")

    def _on_status(self, serve=True):
        super()._on_status(serve)
        self.status_polls += 1
        if serve and self.status_polls % PROGRESS_POLLS != 1:
            return
        try:
            value = _desktop_json.loads(self.read_guest_file(self.paths["runnerProgress"], PROGRESS_READ_LIMIT), object_pairs_hook=_unique)
        except Exception:
            return  # A miss proves nothing: the runner may be replacing the file.
        if type(value) is not dict or value.get("operationId") != self.op:
            return
        stage, elapsed = value.get("stage"), value.get("elapsedSeconds")
        if type(stage) is not str or _desktop_re.fullmatch(r"[a-z][a-z-]{0,31}", stage) is None:
            return
        progress = {"stage": stage, "elapsedSeconds": elapsed if type(elapsed) is int else None, "poll": self.status_polls}
        temporary = self.data / "desktop-progress.json.new"
        temporary.write_bytes((_desktop_json.dumps(progress, sort_keys=True) + "\n").encode())
        _desktop_os.replace(temporary, self.data / "desktop-progress.json")

    def stage_results(self):
        guest = self.guest()
        try:
            raw = self.read_guest_file(self.paths["runnerSummary"], SUMMARY_READ_LIMIT)
        except Exception:
            raise KnownFailure("desktop_runner_summary_missing") from None
        summary = desktop_summary(raw, self.plan, guest)
        self._keep("desktop-test-summary.json", raw)
        self.summary_record = {"bytes": len(raw), "sha256": _sha(raw)}
        self.runner = summary
        result = summary["results"]
        if result is not None:
            try:
                data = self.read_guest_file(self.paths["runnerResults"], result["bytes"], truncate_wires=True)
            except Exception:
                raise KnownFailure("desktop_results_read_lost") from None
            if len(data) != result["bytes"] or _sha(data) != result["sha256"]:
                raise KnownFailure("desktop_results_hash")
            self._keep("desktop-test-results.zip", data)
            self.results = {"bytes": len(data), "sha256": result["sha256"], "xmlFiles": result["xmlFiles"]}
        if summary["outcome"] != "completed":
            raise KnownFailure("desktop_runner:" + token(summary["failedStage"]) + ":" + token(summary["failure"]))

    def cleanup_targets(self):
        """Every archive endpoint this job created: by its verified pin, size included, or, when its push or
        verification did not complete, by the endpoint's volume and file index alone."""
        targets = []
        for role in ARCHIVE_ROLES:
            pin = self.file_pins.get(role)
            if pin is not None:
                identity = pin["nativeIdentity"]
                targets.append({"path": pin["path"], "volumeSerial": identity["volumeSerial"], "fileIndex": identity["fileIndex"],
                                "sizeBytes": identity["sizeBytes"], "sizeKnown": True})
            elif role in self.archive_endpoints:
                targets.append({**self.archive_endpoints[role], "sizeBytes": 0, "sizeKnown": False})
        return targets

    def archives_released(self):
        """Nothing can hold the archives any more: the owner exited, or no task was ever launched (a known failure
        before the run, or a run refused before launch). Combined with a known exit and no open program."""
        state = (self.task or {}).get("state")
        return state in ("task-finished", "refused-before-launch") or self.task is None

    def stage_cleanup(self):
        """Delete the pushed archives; whatever ran from them has exited, or never started."""
        targets = self.cleanup_targets()

        def decide(value):
            rows = value.get("targets")
            if (value.get("state") != "desktop-test-archives-cleaned" or type(rows) is not list or len(rows) != len(targets)
                    or [row.get("path") for row in rows] != [target["path"] for target in targets]
                    or any(row.get("state") not in ("deleted", "absent", "held", "not-the-published-file") for row in rows)):
                raise ValueError("desktop_cleanup_reply")
            return {"states": [row["state"] for row in rows], "freeBytes": value.get("freeBytes")}
        m = {"schemaVersion": 1, "action": "desktop-cleanup", "operationId": self.op, "workspace": self.workspace, "drive": self._drive(),
             "targets": targets}
        try:
            outcome = self._desktop_program("desktop-cleanup", CLEANUP_TEMPLATE, m, decide)
        except ValueError:
            self.cleanup = {"state": "failed"}
            raise KnownFailure("desktop_cleanup_unreadable") from None
        complete = all(state in ("deleted", "absent") for state in outcome["states"])
        self.cleanup = {"state": "complete" if complete else "incomplete", "archives": outcome["states"],
                        "freeBytes": outcome["freeBytes"] if type(outcome["freeBytes"]) is int else None}
        if not complete:
            raise KnownFailure("desktop_cleanup_incomplete")

    def desktop_receipt(self):
        runner = self.runner or {}
        gradle = runner.get("gradle") or {}
        work = runner.get("workRoot") or {}
        return {"sourceCommit": self.desktop["sourceCommit"], "archives": {role: self.plan["packages"][role]["sha256"] for role in ARCHIVE_ROLES},
                "runnerOutcome": runner.get("outcome"), "runnerFailedStage": runner.get("failedStage"), "runnerFailure": runner.get("failure"),
                "gradleExitCode": gradle.get("exitCode"), "gradleDeadline": gradle.get("deadline"), "gradleSeconds": gradle.get("seconds"),
                "summary": self.summary_record, "results": self.results, "workRootDeleted": work.get("deleted"),
                "disk": self.disk, "cleanup": self.cleanup}

    def run(self):
        code, failure = EXIT_PASSED, None
        stages = (("anchor", self.stage_anchor), ("context", self.stage_context), ("publish", self.stage_publish),
                  ("requests", self.stage_requests), ("run", self.stage_run), ("results", self.stage_results))
        try:
            for name, action in stages:
                self.stage = name
                action()
        except Refused as error:
            code, failure = EXIT_REFUSED, token(error)
        except KnownFailure as error:
            code, failure = EXIT_FAILED, token(error)
        except Unknown as error:
            code, failure = EXIT_UNKNOWN, token(error)
        except Exception as error:
            if self.anchored:
                code, failure = EXIT_UNKNOWN, "unexpected:" + type(error).__name__
            else:  # Only guest-ping went out. A partly saved intent still blocks through prior_fence_open.
                code, failure = EXIT_REFUSED, "host_prepare:" + type(error).__name__
        failed_stage = self.stage
        # Evidence only after the last program returned, as in a scenario row; it touches nothing.
        if self.published and not self.program_open:
            self.stage = "evidence"
            try:
                self.stage_evidence()
            except KnownFailure as error:
                if code == EXIT_PASSED:
                    code, failure, failed_stage = EXIT_FAILED, token(error), "evidence"
            except Exception as error:
                code = EXIT_UNKNOWN
                failure = failure or token(error if isinstance(error, Unknown) else "unexpected:" + type(error).__name__)
        # The archives go once the exit is known, no program is open and nothing can hold them: after the owner exited,
        # and also after a known failure before any task launched (they were pushed, then the job stopped). An open
        # outcome, a parked owner among them, keeps everything.
        if code in KNOWN_EXITS and not self.program_open and self.archives_released() and self.cleanup_targets():
            self.stage = "cleanup"
            try:
                self.stage_cleanup()
            except KnownFailure as error:
                if code == EXIT_PASSED:
                    code, failure, failed_stage = EXIT_FAILED, token(error), "cleanup"
            except Exception as error:
                self.cleanup = {"state": "unknown"}
                if code == EXIT_PASSED:
                    failed_stage = "cleanup"
                code = EXIT_UNKNOWN
                failure = failure or token(error if isinstance(error, Unknown) else "unexpected:" + type(error).__name__)
        self.stage = "receipt" if code == EXIT_PASSED else failed_stage
        return self._finish(code, failure)

    def _finish(self, code, failure):
        try:
            if self.owns_data:
                context = None if self.context is None else {**self.context, **{
                    "hardwareUuid": self.raw_context["boot"]["hardwareUuid"], "machineGuid": self.raw_context["boot"]["machineGuid"]}}
                receipt = build_receipt(self.plan, exit_code=code, stage=self.stage, failure=failure, context=context,
                                        task=self.task, evidence=self.evidence, guest_programs=self.programs,
                                        windows={"installedPackage": False, "packageSha256": None})
                receipt["desktopTest"] = self.desktop_receipt()
                raw = (_desktop_json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
                if len(raw) > RECEIPT_BYTES:
                    raise ValueError("receipt_bound")
                self._keep("scenario-receipt.json", raw)
                self._keep("job-exit.json", (_desktop_json.dumps({"schemaVersion": 1, "operationId": self.op, "exitCode": code,
                                                                  "fenceAnchored": self.anchored}, sort_keys=True) + "\n").encode())
            if self.anchored and code in KNOWN_EXITS:
                self.rt.save("direct-guest-" + self.op + ".terminal.json", {"exited": True, "exitcode": code})
        except Exception:
            code, failure = EXIT_UNKNOWN, "finish_failed"
        self.rt.emit(_desktop_json.dumps({"schemaVersion": 1, "operationId": self.op, "scenarioExit": code, "failure": failure},
                                         sort_keys=True, separators=(",", ":")))
        return code


def run_job(rt, plan, files):  # Rebinds the base job's name in the rendered program only.
    return DesktopTestJob(rt, plan, files).run()
