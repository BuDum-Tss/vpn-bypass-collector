# Batch add/delete of IPv4 routes through the Windows IP Helper API (CreateIpForwardEntry2 /
# DeleteIpForwardEntry2). One process handles thousands of routes in about a second, while a separate
# route.exe call per route takes ~0.15 s each. Used by the agent for large sets (Russian subnets).
#
#   powershell -File route-batch.ps1 -Path ops.json     # ops: [{op:"add"|"del", net, plen, gw, ifx, metric}]
#   powershell -File route-batch.ps1 -SelfTest          # read-only check of the struct layout
#
# Output (last line): JSON array of Win32 codes (0 = ok) or, for -SelfTest, {"ok":true|false,...}.
# Note: keep this file ASCII-only (Windows PowerShell 5.1 reads BOM-less files as ANSI).
param([string]$Path, [switch]$SelfTest)
$ErrorActionPreference = 'Stop'

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Rt {
  [DllImport("iphlpapi.dll")] static extern void InitializeIpForwardEntry(IntPtr row);
  [DllImport("iphlpapi.dll")] static extern int CreateIpForwardEntry2(IntPtr row);
  [DllImport("iphlpapi.dll")] static extern int DeleteIpForwardEntry2(IntPtr row);
  [DllImport("iphlpapi.dll")] static extern int GetIpForwardEntry2(IntPtr row);
  // MIB_IPFORWARD_ROW2 (104 bytes): 0 LUID(8) | 8 ifIndex | 12 prefix SOCKADDR_INET(28) | 40 prefixLen |
  // 44 nextHop SOCKADDR_INET(28) | 72 sitePrefixLen | 76 validLife | 80 prefLife | 84 metric | 88 protocol | ...
  const int SIZE = 104;
  static IntPtr Build(uint net, int plen, uint gw, int ifx, uint metric) {
    IntPtr p = Marshal.AllocHGlobal(SIZE);
    for (int i = 0; i < SIZE; i += 4) Marshal.WriteInt32(p, i, 0);
    InitializeIpForwardEntry(p);
    Marshal.WriteInt32(p, 8, ifx);
    Marshal.WriteInt16(p, 12, 2);            // AF_INET (destination prefix)
    Marshal.WriteInt32(p, 16, unchecked((int)net));
    Marshal.WriteByte(p, 40, (byte)plen);
    Marshal.WriteInt16(p, 44, 2);            // AF_INET (next hop)
    Marshal.WriteInt32(p, 48, unchecked((int)gw));
    Marshal.WriteInt32(p, 84, unchecked((int)metric));
    Marshal.WriteInt32(p, 88, 3);            // MIB_IPPROTO_NETMGMT (same as a manually added route)
    return p;
  }
  public static int Add(uint net, int plen, uint gw, int ifx, uint metric) {
    IntPtr p = Build(net, plen, gw, ifx, metric);
    try { return CreateIpForwardEntry2(p); } finally { Marshal.FreeHGlobal(p); }
  }
  public static int Del(uint net, int plen, uint gw, int ifx, uint metric) {
    IntPtr p = Build(net, plen, gw, ifx, metric);
    try { return DeleteIpForwardEntry2(p); } finally { Marshal.FreeHGlobal(p); }
  }
  // Read an existing route and return: code, metric, prefixLen (checks that offsets are right).
  public static long[] Read(uint net, int plen, uint gw, int ifx) {
    IntPtr p = Build(net, plen, gw, ifx, 0);
    try {
      int code = GetIpForwardEntry2(p);
      return new long[] { code, Marshal.ReadInt32(p, 84), Marshal.ReadByte(p, 40), (long)unchecked((uint)Marshal.ReadInt32(p, 48)) };
    } finally { Marshal.FreeHGlobal(p); }
  }
}
"@

function IpToUInt([string]$ip) { return [BitConverter]::ToUInt32(([Net.IPAddress]::Parse($ip)).GetAddressBytes(), 0) }

if ($SelfTest) {
  # Compare what the API reads back for the current default route with what Get-NetRoute says.
  $d = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.NextHop -ne '0.0.0.0' } |
       Sort-Object { $_.RouteMetric + $_.InterfaceMetric } | Select-Object -First 1
  if (-not $d) { '{"ok":false,"why":"no default route"}'; exit 0 }
  $gwU = [long](IpToUInt $d.NextHop)
  $r = [Rt]::Read(0, 0, [uint32]$gwU, [int]$d.ifIndex)
  $ok = ($r[0] -eq 0) -and ($r[1] -eq [long]$d.RouteMetric) -and ($r[2] -eq 0) -and ($r[3] -eq $gwU)
  # second check on a host route of ours (metric 1, /32): verifies prefix length and metric offsets
  $mine = Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.RouteMetric -eq 1 -and $_.DestinationPrefix -like '*/32' -and $_.NextHop -ne '0.0.0.0' } | Select-Object -First 1
  $ok2 = $true
  if ($mine) {
    $ip = $mine.DestinationPrefix.Split('/')[0]
    $m = [Rt]::Read((IpToUInt $ip), 32, (IpToUInt $mine.NextHop), [int]$mine.ifIndex)
    $ok2 = ($m[0] -eq 0) -and ($m[1] -eq 1) -and ($m[2] -eq 32)
  }
  ('{{"ok":{0},"defaultRoute":{1},"hostRoute":{2},"code":{3},"metric":{4},"expected":{5}}}' -f ($ok -and $ok2).ToString().ToLower(), $ok.ToString().ToLower(), $ok2.ToString().ToLower(), $r[0], $r[1], $d.RouteMetric)
  exit 0
}

$ops = Get-Content -Raw -Path $Path | ConvertFrom-Json
$codes = New-Object 'System.Collections.Generic.List[int]'
foreach ($o in $ops) {
  $net = IpToUInt $o.net
  $gw  = IpToUInt $o.gw
  if ($o.op -eq 'add') { $c = [Rt]::Add($net, [int]$o.plen, $gw, [int]$o.ifx, [uint32]$o.metric) }
  else                 { $c = [Rt]::Del($net, [int]$o.plen, $gw, [int]$o.ifx, [uint32]$o.metric) }
  $codes.Add($c)
}
'[' + ($codes -join ',') + ']'
