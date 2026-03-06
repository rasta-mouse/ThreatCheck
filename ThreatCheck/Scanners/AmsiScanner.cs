using System;
using System.Text;

using static ThreatCheck.NativeMethods;

namespace ThreatCheck.Scanners;

internal class AmsiScanner : Scanner, IDisposable
{
    private readonly IntPtr _amsiContext;
    private readonly IntPtr _amsiSession;

    private byte[] _fileBytes;

    // The appName appears to matter in the detections that will occur especially for scripts. Giving it a powershell
    // app appears to be the most aggressive in producing detections so use that as the default.
    public AmsiScanner(string appName = @"PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_5.1.22621.2506")
    {
        AmsiInitialize(appName, out _amsiContext);
        AmsiOpenSession(_amsiContext, out _amsiSession);
    }

    public void AnalyzeBytes(byte[] bytes)
    {
        _fileBytes = bytes;

        var status = ScanBuffer(_fileBytes);
        
        if (status is not AmsiResult.AmsiResultDetected)
        {
            CustomConsole.WriteOutput("No threat found!");
            return;
        }

        Malicious = true;

        CustomConsole.WriteOutput($"Target file size: {_fileBytes.Length} bytes");
        CustomConsole.WriteOutput("Analyzing...");

        var splitArray = new byte[_fileBytes.Length / 2];
        Buffer.BlockCopy(_fileBytes, 0, splitArray, 0, _fileBytes.Length / 2);
        var lastgood = 0;

        while (!Complete)
        {
#if DEBUG
            CustomConsole.WriteDebug($"Testing {splitArray.Length} bytes");
#endif
            var detectionStatus = ScanBuffer(splitArray);

            if (detectionStatus is AmsiResult.AmsiResultDetected)
            {
#if DEBUG
                CustomConsole.WriteDebug("Threat found, splitting");
#endif
                var tmpArray = HalfSplitter(splitArray, lastgood);
                Array.Resize(ref splitArray, tmpArray.Length);
                Array.Copy(tmpArray, splitArray, tmpArray.Length);
            }
            else
            {
#if DEBUG
                CustomConsole.WriteDebug("No threat found, increasing size");
#endif
                lastgood = splitArray.Length;
                var tmpArray = Overshot(_fileBytes, splitArray.Length); //Create temp array with 1.5x more bytes
                Array.Resize(ref splitArray, tmpArray.Length);
                Buffer.BlockCopy(tmpArray, 0, splitArray, 0, tmpArray.Length);
            }
        }
    }

    private AmsiResult ScanBuffer(byte[] buffer)
    {
        AmsiScanBuffer(_amsiContext, buffer, (uint)buffer.Length, "", _amsiSession, out var result);
        return result;
    }

    private AmsiResult ScanBuffer(byte[] buffer, IntPtr session)
    {
        AmsiScanBuffer(_amsiContext, buffer, (uint)buffer.Length, "", session, out var result);
        return result;
    }

    public bool RealTimeProtectionEnabled
    {
        get
        {
            var sample = Encoding.UTF8.GetBytes("Invoke-Expression 'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'");
            var result = ScanBuffer(sample, IntPtr.Zero);

            return result == AmsiResult.AmsiResultDetected;
        }
    }

    public void Dispose()
    {
        AmsiCloseSession(_amsiContext, _amsiSession);
        AmsiUninitialize(_amsiContext);
    }
}