// Native Windows-only fixture. It creates a private copy of this PowerShell
// image, so Restart Manager must identify a real process holding a retained
// installation executable without installing or changing an MSI.
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class InstallerInventoryFixtures {
    static void Require(bool value,string message) { if (!value) throw new InvalidOperationException(message); }
    static string Principal() { using (WindowsIdentity identity=WindowsIdentity.GetCurrent()) return identity.User.Value; }
    static string FixtureImage() { return Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe"); }
    static void CopyFixtureImage(string target) { File.Copy(FixtureImage(),target,true); }
    static VpnInstallNative.ExecutableReplacementSet Installation(SafeFileHandle directory,string principal) {
        return new VpnInstallNative.ExecutableReplacementSet(directory,principal);
    }
    static Process StartCopy(string image,int milliseconds) {
        if (milliseconds<1 || milliseconds>20000) throw new ArgumentException("Fixture delay rejected");
        ProcessStartInfo start=new ProcessStartInfo(image,
            "-NoProfile -NonInteractive -Command \"Start-Sleep -Milliseconds "+milliseconds+"\"");
        start.UseShellExecute=false; return Process.Start(start);
    }
    static void Stop(Process process) {
        if (process==null) return;
        try { if (!process.HasExited) process.Kill(); } catch { }
        try { process.WaitForExit(5000); } catch { }
        process.Dispose();
    }
    static void DeleteDirectory(string directory) {
        if (Directory.Exists(directory)) Directory.Delete(directory,true);
    }
    public static string[] Run() {
        string directory=Path.Combine(Path.GetTempPath(),"vpn-install-inventory-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory); Process child=null;
        try {
            CopyFixtureImage(Path.Combine(directory,"vpn-control.exe"));
            CopyFixtureImage(Path.Combine(directory,"vpn-control-cli.exe"));
            using (SafeFileHandle retainedDirectory=VpnInstallNative.OpenDirectory(directory))
            using (VpnInstallNative.ExecutableReplacementSet installation=Installation(retainedDirectory,Principal())) {
                uint self=(uint)Process.GetCurrentProcess().Id;
                Console.WriteLine("STEP:idle");
                Require(VpnInstallHelperProcessInventory.TryNoAdmittedInstallationCopies(installation,self,self),
                    "Idle retained installation was not ready");
                Console.WriteLine("STEP:live-start"); child=StartCopy(Path.Combine(directory,"vpn-control.exe"),20000);
                Require(child!=null && !child.HasExited,"Fixture image did not start");
                // A real mapped installation image is a Restart Manager resource
                // candidate and must block without any attempt to stop it.
                Require(!VpnInstallHelperProcessInventory.TryNoAdmittedInstallationCopies(installation,self,self),
                    "Live installation image was silently skipped");
                // The same live generation is admitted only when its exact pinned
                // process identity is the explicit worker identity.
                Console.WriteLine("STEP:authorized"); Require(VpnInstallHelperProcessInventory.TryNoAdmittedInstallationCopies(installation,self,(uint)child.Id),
                    "Exact authorized worker identity was not excluded");
                Stop(child); child=null;
                // Exercise a process that can leave between resource enumeration
                // and its retained image query. After it exits, a fresh bounded
                // inventory must not retain a stale refusal.
                Console.WriteLine("STEP:race"); child=StartCopy(Path.Combine(directory,"vpn-control.exe"),100);
                Thread.Sleep(75);
                VpnInstallHelperProcessInventory.TryNoAdmittedInstallationCopies(installation,self,self);
                Require(child.WaitForExit(5000),"Race fixture process did not exit"); child.Dispose(); child=null;
                Require(VpnInstallHelperProcessInventory.TryNoAdmittedInstallationCopies(installation,self,self),
                    "Exited candidate remained an installation copy");
            }
            return new string[] {"idle-ready","live-copy-blocked","exact-worker-excluded","race-refresh-ready"};
        } finally {
            Stop(child);
            DeleteDirectory(directory);
        }
    }
}
