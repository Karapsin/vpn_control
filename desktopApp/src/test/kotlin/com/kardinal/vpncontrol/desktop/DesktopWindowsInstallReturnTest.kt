package com.kardinal.vpncontrol.desktop

import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.test.*
import org.junit.Assume.assumeTrue

/** Executes the worker's actual return builder without starting an installer or a product process. */
class DesktopWindowsInstallReturnTest {
    @Test fun fixedWorkerReturnsToTheExactWorkspaceWithItsCapturedPresentationIntent() {
        assumeTrue(System.getProperty("os.name").startsWith("Windows", true))
        val worker = javaClass.getResourceAsStream("/windows-install-user.ps1")!!.bufferedReader().use { it.readText() }
        val definitions = worker.substringBefore("\n\$owner = \$null")
        check(definitions.contains("function New-ReturnedOwnerStartInfo("))
        val directory = "D:\\Работа 空間\\VPN ' & $ % workspace"
        val encodedDirectory = Base64.getEncoder().encodeToString(directory.encodeToByteArray())
        val script = definitions + "\n" + """
            ${'$'}ErrorActionPreference='Stop'
            Add-Type -TypeDefinition @'
            using System;
            using System.Runtime.InteropServices;
            public static class VpnInstallReturnArguments {
                [DllImport("shell32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
                static extern IntPtr CommandLineToArgvW(string command, out int count);
                [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr value);
                public static string[] Parse(string command) {
                    int count;
                    IntPtr values=CommandLineToArgvW(command, out count);
                    if (values==IntPtr.Zero) throw new Exception("Argument parser unavailable");
                    try {
                        string[] result=new string[count];
                        for(int i=0;i<count;i++) result[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(values,i*IntPtr.Size));
                        return result;
                    } finally { LocalFree(values); }
                }
            }
            '@
            ${'$'}directory=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$encodedDirectory'))
            foreach (${'$'}frontend in @(${'$'}false,${'$'}true)) {
                ${'$'}request=@{launcher='C:\Users\Test\VPN Control\vpn-control.exe';stateDirectory=${'$'}directory}
                if (${'$'}frontend) { ${'$'}request['frontendPid']=123L }
                ${'$'}start=New-ReturnedOwnerStartInfo ${'$'}request
                if (${'$'}start.UseShellExecute -or ${'$'}start.FileName -cne ${'$'}request['launcher']) { throw 'Wrong return authority' }
                ${'$'}arguments=[VpnInstallReturnArguments]::Parse(('"'+${'$'}start.FileName+'" '+${'$'}start.Arguments))
                ${'$'}expectedCount=if (${'$'}frontend) {3} else {4}
                if (${'$'}arguments.Count -ne ${'$'}expectedCount -or ${'$'}arguments[0] -cne ${'$'}request['launcher'] -or
                    ${'$'}arguments[1] -cne '--state-dir' -or ${'$'}arguments[2] -cne ${'$'}directory) { throw 'Workspace arguments changed' }
                if (-not ${'$'}frontend -and ${'$'}arguments[3] -cne 'serve') { throw 'Disconnected owner return omitted' }
            }
            Write-Output 'WORKSPACE_RETURN_OK'
        """.trimIndent()
        val process = ProcessBuilder("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
            Base64.getEncoder().encodeToString(script.toByteArray(Charsets.UTF_16LE)))
            .redirectErrorStream(true).start()
        try {
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Fixed return builder timed out")
            val output = process.inputStream.bufferedReader().readText()
            assertEquals(0, process.exitValue(), output)
            assertTrue(output.contains("WORKSPACE_RETURN_OK"), output)
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
