# Reads DeskHop USB host health (feature report 8) from the board this PC is plugged into.
# That board answers for itself and for the other board (relayed over the inter-board link).
#   powershell -ExecutionPolicy Bypass -File host-status.ps1
Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class DeskHopHid {
  [StructLayout(LayoutKind.Sequential)] struct SP_DEVICE_INTERFACE_DATA { public int cbSize; public Guid g; public int Flags; public IntPtr Reserved; }
  [StructLayout(LayoutKind.Sequential)] public struct HIDP_CAPS { public ushort Usage, UsagePage, InputLen, OutputLen, FeatureLen; [MarshalAs(UnmanagedType.ByValArray, SizeConst=17)] public ushort[] r; public ushort a,b,c,d,e,f,g,h,i,j; }
  [DllImport("hid.dll")] static extern void HidD_GetHidGuid(out Guid g);
  [DllImport("hid.dll")] static extern bool HidD_GetPreparsedData(SafeFileHandle h, out IntPtr p);
  [DllImport("hid.dll")] static extern bool HidD_FreePreparsedData(IntPtr p);
  [DllImport("hid.dll")] static extern int HidP_GetCaps(IntPtr p, out HIDP_CAPS c);
  [DllImport("hid.dll")] static extern bool HidD_GetFeature(SafeFileHandle h, byte[] b, int len);
  [DllImport("setupapi.dll")] static extern IntPtr SetupDiGetClassDevs(ref Guid g, IntPtr e, IntPtr w, int f);
  [DllImport("setupapi.dll")] static extern bool SetupDiEnumDeviceInterfaces(IntPtr s, IntPtr d, ref Guid g, int i, ref SP_DEVICE_INTERFACE_DATA o);
  [DllImport("setupapi.dll", CharSet=CharSet.Auto)] static extern bool SetupDiGetDeviceInterfaceDetail(IntPtr s, ref SP_DEVICE_INTERFACE_DATA d, IntPtr o, int sz, out int req, IntPtr di);
  [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr s);
  [DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)] static extern SafeFileHandle CreateFile(string n, uint a, uint s, IntPtr sa, uint c, uint f, IntPtr t);

  // Returns the raw feature report (report ID first) from every DeskHop status collection found.
  public static List<byte[]> Read() {
    var result = new List<byte[]>();
    Guid g; HidD_GetHidGuid(out g);
    IntPtr set = SetupDiGetClassDevs(ref g, IntPtr.Zero, IntPtr.Zero, 0x12);
    try {
      var d = new SP_DEVICE_INTERFACE_DATA(); d.cbSize = Marshal.SizeOf(d);
      for (int i = 0; SetupDiEnumDeviceInterfaces(set, IntPtr.Zero, ref g, i, ref d); i++) {
        int req; SetupDiGetDeviceInterfaceDetail(set, ref d, IntPtr.Zero, 0, out req, IntPtr.Zero);
        IntPtr buf = Marshal.AllocHGlobal(req);
        try {
          Marshal.WriteInt32(buf, IntPtr.Size == 8 ? 8 : 4 + Marshal.SystemDefaultCharSize);
          if (!SetupDiGetDeviceInterfaceDetail(set, ref d, buf, req, out req, IntPtr.Zero)) continue;
          string path = Marshal.PtrToStringAuto(buf + 4);
          if (path.ToLower().IndexOf("vid_1209&pid_c000") < 0) continue;
          using (var h = CreateFile(path, 0xC0000000, 3, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (h.IsInvalid) continue;
            IntPtr pp; if (!HidD_GetPreparsedData(h, out pp)) continue;
            HIDP_CAPS caps; HidP_GetCaps(pp, out caps); HidD_FreePreparsedData(pp);
            if (caps.UsagePage != 0xFF00 || caps.Usage != 0x20) continue;
            var report = new byte[caps.FeatureLen]; report[0] = 8;
            if (HidD_GetFeature(h, report, report.Length)) result.Add(report);
          }
        } finally { Marshal.FreeHGlobal(buf); }
      }
    } finally { SetupDiDestroyDeviceInfoList(set); }
    return result;
  }
}
"@

function Format-Board([byte[]]$r, [int]$off, [string]$name) {
    $flags = $r[$off + 1]
    $age = $r[$off + 8]
    if (-not ($flags -band 0x80)) { return "${name}: no data" + $(if ($age -eq 255) { " (never heard from)" } else { "" }) }
    $bits = @()
    if ($flags -band 0x04) { $bits += "attached" } else { $bits += "socket empty" }
    if ($flags -band 0x08) { $bits += "mounted" }
    if ($flags -band 0x10) { $bits += "keyboard" }
    if ($flags -band 0x20) { $bits += "mouse" }
    if ($flags -band 0x01) { $bits += "HUB" }
    if ($flags -band 0x02) { $bits += "ENUMERATING" }
    $slots = $r[$off]
    $limit = if ($flags -band 0x01) { 4 } else { 1 }
    $warn = if ($slots -gt $limit) { "  <-- LEAK: more slots than devices" } else { "" }
    $up = [BitConverter]::ToUInt16($r, $off + 6)
    "{0}: slots {1}/4, {2} | abandoned {3}, stale freed {4}, addr fails {5}, recoveries {6} | up {7}h{8:00}m, data {9}s old{10}" -f `
        $name, $slots, ($bits -join ", "), $r[$off + 2], $r[$off + 3], $r[$off + 4], $r[$off + 5], [math]::Floor($up / 60), ($up % 60), $age, $warn
}

$reports = [DeskHopHid]::Read()
if ($reports.Count -eq 0) {
    Write-Output "No DeskHop status report found (old firmware, or the box isn't plugged into this PC)."
    exit 1
}
foreach ($r in $reports) {
    # r[0] = report ID, r[1] = format, r[2] = answering board, then A block (8 + age), B block (8 + age)
    Write-Output ("answered by board {0} (format {1})" -f @('A', 'B')[$r[2]], $r[1])
    Write-Output (Format-Board $r 3 'A')
    Write-Output (Format-Board $r 12 'B')
}
