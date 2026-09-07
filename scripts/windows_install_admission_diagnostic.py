#!/usr/bin/env python3
"""Read-only diagnostic for admission failure in an exact Windows app image.

Run only after a packaged launcher failed. This does not authorize installation
or replace the launcher's original exit/stdout/stderr result.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile

JAVA_SOURCE = r'''import java.lang.reflect.*;
import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.nio.ByteBuffer;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.*;
import java.util.jar.*;

public final class WindowsInstallAdmissionDiagnostic {
  private static final String PACKAGE = "com.kardinal.vpncontrol.desktop.";
  private static final Set<String> SAFE_MESSAGES = Set.of(
    "Unsupported installer access mask", "Untrusted installer mutation rights", "Untrusted installer owner",
    "Reparse/device path rejected", "Unexpected installer object type", "Hard-linked installer file rejected",
    "Unrestricted installer DACL", "Unsupported installer ACE", "Unexpected cancellation principal",
    "Untrusted installation volume", "Unpinned mutable ancestor", "Unlinked ancestor witness",
    "Malformed installation gate", "Unapproved launcher", "BUSY", "Implicit diagnostic classpath expansion");
  private static String decoded(String text) throws Exception {
    return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
      .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(Base64.getDecoder().decode(text))).toString();
  }
  private static Throwable original(Throwable value) {
    while (value instanceof InvocationTargetException && value.getCause() != null) value = value.getCause();
    return value;
  }
  private static Object call(Object target, String name, Object... arguments) throws Throwable {
    Method method = Arrays.stream(target.getClass().getMethods()).filter(m -> m.getName().equals(name)
      && m.getParameterCount() == arguments.length).findFirst().orElseThrow(NoSuchMethodException::new);
    method.setAccessible(true);
    try { return method.invoke(target, arguments); } catch (InvocationTargetException error) { throw original(error); }
  }
  private static Map<String,Object> failure(Throwable thrown) {
    Throwable error = original(thrown); Map<String,Object> result = new LinkedHashMap<>();
    result.put("class", error.getClass().getName());
    result.put("message", error.getMessage() != null && SAFE_MESSAGES.contains(error.getMessage()) ? error.getMessage() : null);
    if (error.getClass().getName().equals(PACKAGE + "WindowsInstallNativeFailure")) {
      try { result.put("nativeCode", call(error, "getCode")); } catch (Throwable ignored) { result.put("nativeCodeUnavailable", true); }
    }
    List<String> frames = new ArrayList<>();
    for (StackTraceElement frame : error.getStackTrace()) {
      if (frames.size() == 8) break;
      if (frame.getClassName().startsWith(PACKAGE)) frames.add(frame.getClassName() + "#" + frame.getMethodName() + ":" + frame.getLineNumber());
    }
    result.put("frames", frames); return result;
  }
  private static void addAncestors(LinkedHashSet<String> paths, Path path) {
    List<String> reverse = new ArrayList<>();
    for (Path current = path; current != null && reverse.size() < 32; current = current.getParent()) reverse.add(current.toString());
    Collections.reverse(reverse); paths.addAll(reverse);
  }
  private static List<Object> metadata(Object nativeObject, Path launcher) {
    List<Object> records = new ArrayList<>(); LinkedHashSet<String> paths = new LinkedHashSet<>();
    addAncestors(paths, launcher.toAbsolutePath().normalize().getParent());
    try {
      Path programData = Path.of((String)call(nativeObject,"programData"));
      addAncestors(paths, programData); paths.add(programData.resolve("vpn-control-install-jobs").toString());
    } catch (Throwable error) { records.add(Map.of("phase", "programData", "failure", failure(error))); }
    int visited = 0;
    for (String path : paths) {
      if (visited++ >= 48) { records.add(Map.of("truncated",true)); break; }
      Map<String,Object> record = new LinkedHashMap<>(); record.put("path",path); Object handle = null;
      try {
        handle=call(nativeObject,"openDirectory",path);
        record.put("canonicalPath",call(nativeObject,"canonicalPath",handle));
        record.put("persistentAcl",call(nativeObject,"persistentAcl",handle));
        Object info=call(nativeObject,"inspect",handle);
        for (String field : List.of("Owner","Directory","Attributes","ReparseTag","Disk","Links")) record.put(field.substring(0,1).toLowerCase(Locale.ROOT)+field.substring(1),call(info,"get"+field));
        Object acl=call(info,"getDacl"); List<Object> entries = new ArrayList<>();
        if (acl instanceof Iterable<?>) for(Object ace:(Iterable<?>)acl) {
          if(entries.size()==64){record.put("daclTruncated",true);break;}
          Map<String,Object> entry=new LinkedHashMap<>();for(String field:List.of("Type","Flags","Mask","Sid")) entry.put(field.toLowerCase(Locale.ROOT),call(ace,"get"+field));entries.add(entry);
        }
        record.put("dacl",acl == null ? null : entries);
      } catch(Throwable error) { record.put("failure",failure(error)); }
      finally { if(handle!=null) try {call(nativeObject,"close",handle);} catch(Throwable error) {record.put("closeFailure",failure(error));} }
      records.add(record);
    }
    return records;
  }
  private static String json(Object value) {
    if(value==null)return "null";
    if(value instanceof Boolean || value instanceof Number)return value.toString();
    if(value instanceof Map<?,?>){List<String> fields=new ArrayList<>();for(Map.Entry<?,?> entry:((Map<?,?>)value).entrySet())fields.add(json(entry.getKey().toString())+":"+json(entry.getValue()));return "{"+String.join(",",fields)+"}";}
    if(value instanceof Iterable<?>){List<String> items=new ArrayList<>();for(Object item:(Iterable<?>)value)items.add(json(item));return "["+String.join(",",items)+"]";}
    String text=value.toString();StringBuilder output=new StringBuilder("\"");
    for(int i=0;i<text.length();i++){char c=text.charAt(i);if(c=='\\'||c=='\"')output.append('\\').append(c);else if(c<32||c>126)output.append(String.format(Locale.ROOT,"\\u%04x",(int)c));else output.append(c);}
    return output.append('"').toString();
  }
  public static void main(String[] arguments) {
    Map<String,Object> report=new LinkedHashMap<>();report.put("schemaVersion",1);report.put("javaFeatureVersion",Runtime.version().feature());report.put("processArchitecture",System.getProperty("os.arch"));
    Object nativeObject=null; Path launcher=null; URLClassLoader appLoader=null;
    try {
      if(arguments.length!=0)throw new IllegalArgumentException("Unexpected diagnostic argument");
      Path request=Path.of("admission-request.txt");
      if(Files.size(request)>1048576)throw new IllegalArgumentException("Diagnostic request exceeded its bound");
      List<String> lines=Files.readAllLines(request,StandardCharsets.US_ASCII);
      if(lines.size()<3||lines.size()>514||!lines.get(0).equals("vpn-control-admission-diagnostic-v1"))throw new IllegalArgumentException("Invalid diagnostic request");
      launcher=Path.of(decoded(lines.get(1))); List<URL> urls=new ArrayList<>();
      for(String line:lines.subList(2,lines.size())){
        URI uri=URI.create(decoded(line));
        if(!"file".equals(uri.getScheme())||uri.getRawAuthority()!=null||uri.getRawQuery()!=null||uri.getRawFragment()!=null)throw new IllegalArgumentException("Only captured local files are allowed");
        Path path=Path.of(uri);
        if(!Files.isDirectory(path))try(JarFile jar=new JarFile(path.toFile())){
          Manifest manifest=jar.getManifest();
          String implicit=manifest==null?null:manifest.getMainAttributes().getValue(Attributes.Name.CLASS_PATH);
          if((implicit!=null&&!implicit.isBlank())||jar.getJarEntry("META-INF/INDEX.LIST")!=null)
            throw new IllegalArgumentException("Implicit diagnostic classpath expansion");
        }
        urls.add(uri.toURL());
      }
      appLoader=new URLClassLoader(urls.toArray(URL[]::new),ClassLoader.getPlatformClassLoader());
      Class<?> nativeType=Class.forName(PACKAGE+"JnaWindowsInstallAdmission",true,appLoader);Constructor<?> constructor=nativeType.getDeclaredConstructor();constructor.setAccessible(true);nativeObject=constructor.newInstance();
      report.put("principalSid",call(nativeObject,"currentSid"));
      Class<?> admission=Class.forName(PACKAGE+"DesktopWindowsInstallAdmission",true,appLoader);Object instance=admission.getField("INSTANCE").get(null);
      Method enter=Arrays.stream(admission.getDeclaredMethods()).filter(m->m.getName().equals("enter$default")&&m.getParameterCount()==7).findFirst().orElseThrow(NoSuchMethodException::new);enter.setAccessible(true);
      // Invoke the real adapter directly. A Java Proxy would wrap checked native
      // FILE_NOT_FOUND in UndeclaredThrowableException and change the outcome.
      AutoCloseable lease=(AutoCloseable)enter.invoke(null,instance,launcher,nativeObject,false,null,8,null);
      report.put("admission","accepted");
      try {lease.close();report.put("leaseClosed",true);}catch(Throwable error){report.put("closeFailure",failure(error));}
    } catch(Throwable error) {report.put("admission","rejected");report.put("failure",failure(error));}
    if(nativeObject!=null&&launcher!=null)report.put("ancestrySnapshot",metadata(nativeObject,launcher));
    if(appLoader!=null)try{appLoader.close();}catch(Throwable error){report.put("classLoaderCloseFailure",failure(error));}
    System.out.println(json(report));
  }
}
'''

MAX_OUTPUT_BYTES = 262144

def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pe_machine(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        if len(header) != 64 or header[:2] != b"MZ":
            raise ValueError("Expected a Windows PE executable")
        offset = struct.unpack_from("<I", header, 60)[0]
        if offset > 16 * 1024 * 1024:
            raise ValueError("Invalid PE header offset")
        stream.seek(offset)
        pe = stream.read(6)
        if len(pe) != 6 or pe[:4] != b"PE\0\0":
            raise ValueError("Invalid PE signature")
        return struct.unpack_from("<H", pe, 4)[0]


def run_probe(java, classpath, launcher, timeout_seconds=60):
    """Kept platform-neutral so the exact Java invocation is tested with stubs."""
    with tempfile.TemporaryDirectory(prefix="vpn-admission-diagnostic-") as temporary:
        directory = Path(temporary)
        source = directory / "WindowsInstallAdmissionDiagnostic.java"
        source.write_text(JAVA_SOURCE, encoding="utf-8")
        inputs = (Path(classpath),) if isinstance(classpath, (str, Path)) else tuple(Path(path) for path in classpath)
        if not inputs or len(inputs) > 512:
            raise ValueError("Expected a bounded local classpath")
        values = [str(launcher)]
        for path in inputs:
            path = path.absolute()
            if not path.is_file() and not path.is_dir():
                raise ValueError("Classpath input is unavailable")
            uri = path.as_uri()
            values.append(uri + "/" if path.is_dir() and not uri.endswith("/") else uri)
        lines = ["vpn-control-admission-diagnostic-v1", *[
            base64.b64encode(value.encode("utf-8")).decode("ascii") for value in values]]
        (directory / "admission-request.txt").write_text("\n".join(lines) + "\n", encoding="ascii")
        # JDK 17's Windows launcher narrows Unicode argv through the process ACP.
        # Keep JVM arguments ASCII and read exact UTF-8 paths inside the probe.
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            completed = subprocess.run(
                [str(java), "-Dfile.encoding=UTF-8", "--class-path", ".",
                 "--source", "17", source.name],
                cwd=directory, stdout=output, stderr=errors, timeout=timeout_seconds, check=False,
            )
            output.seek(0); errors.seek(0)
            raw = output.read(MAX_OUTPUT_BYTES + 1)
            error_bytes = errors.read(MAX_OUTPUT_BYTES + 1)
        if completed.returncode != 0:
            # Do not print arbitrary JVM/native exception messages or environment data.
            raise RuntimeError("Admission diagnostic JVM failed with exit " + str(completed.returncode))
        if len(raw) > MAX_OUTPUT_BYTES or len(error_bytes) > MAX_OUTPUT_BYTES:
            raise RuntimeError("Admission diagnostic output exceeded its bound")
        report = json.loads(raw.decode("utf-8"))
        if report.get("schemaVersion") != 1 or report.get("javaFeatureVersion") != 17:
            raise RuntimeError("Admission diagnostic requires a compatible JDK 17")
        if report.get("admission") not in ("accepted", "rejected"):
            raise RuntimeError("Admission diagnostic returned no known outcome")
        report["jvmStderrBytes"] = len(error_bytes)
        return report


def diagnose(launcher, java_home, timeout_seconds=60):
    if os.name != "nt":
        raise RuntimeError("This diagnostic requires native Windows")
    launcher = Path(launcher).absolute()
    java = Path(java_home).absolute() / "bin" / "java.exe"
    if launcher.name.casefold() not in ("vpn-control-cli.exe", "vpn-control.exe"):
        raise ValueError("Expected the packaged application launcher")
    jars = sorted((launcher.parent / "app").glob("*.jar"))
    if not jars or len(jars) > 512:
        raise ValueError("Expected a bounded packaged application JAR inventory")
    inputs = [launcher, java, *jars]
    if any(not path.is_file() or path.is_symlink() for path in inputs):
        raise ValueError("Diagnostic inputs must be regular files")
    machine = pe_machine(java)
    if machine != pe_machine(launcher):
        raise ValueError("JDK and launcher architectures differ")
    before = {str(path): file_hash(path) for path in inputs}
    report = run_probe(java, tuple(jars), launcher, timeout_seconds)
    if any(file_hash(path) != before[str(path)] for path in inputs):
        raise RuntimeError("Diagnostic application or JDK inputs changed")
    expected_arch = {0x8664: {"amd64", "x86_64"}, 0xAA64: {"aarch64", "arm64"}}.get(machine, set())
    if report.get("processArchitecture") not in expected_arch:
        raise RuntimeError("Actual JVM architecture does not match the captured PE")
    report["artifact"] = {
        "launcherSha256": before[str(launcher)], "javaSha256": before[str(java)],
        "peMachine": machine,
        "jars": [{"name": path.name, "sha256": before[str(path)]} for path in jars],
        "probeSourceSha256": hashlib.sha256(JAVA_SOURCE.encode("utf-8")).hexdigest(),
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=60)
    args = parser.parse_args()
    if args.timeout_seconds < 1 or args.timeout_seconds > 300:
        parser.error("diagnostic timeout must be between 1 and 300 seconds")
    try:
        report = diagnose(args.launcher, args.java_home, args.timeout_seconds)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as failure:
        print(json.dumps({"schemaVersion": 1, "diagnostic": "unavailable", "failureClass": type(failure).__name__}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
