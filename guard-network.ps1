# Local route inspection only: discovery does not contact an IP lookup service.
function Get-GuardNetworkAdapters {
    @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
}
function Get-GuardRouteIndex([string]$Address) {
    $routes=@(Find-NetRoute -RemoteIPAddress $Address -ErrorAction Stop)
    $indices=@($routes | ForEach-Object { $_.InterfaceIndex } | Sort-Object -Unique)
    if ($indices.Count -ne 1) { throw 'The selected network route is ambiguous.' }
    [int]$indices[0]
}
function Get-GuardVpnAdapter([string]$PinnedGuid) {
    $adapters=@(Get-GuardNetworkAdapters)
    # Probe both halves of IPv4 space. Split /1 tunnel routes must work too.
    # These are routing-table lookups, not packets sent to these addresses.
    $indices=@(@('1.1.1.1','9.9.9.9','193.0.0.1','200.1.1.1') | ForEach-Object { Get-GuardRouteIndex $_ } | Sort-Object -Unique)
    if ($indices.Count -ne 1) { throw 'Internet routes use different interfaces. A full-tunnel VPN is required.' }
    $candidates=@($adapters | Where-Object { $_.ifIndex -eq $indices[0] -and "$($_.Status)" -eq 'Up' -and $_.HardwareInterface -eq $false })
    if ($candidates.Count -ne 1) { throw 'No active VPN tunnel owns the internet route. Connect a full-tunnel VPN first.' }
    $vpn=$candidates[0]
    if ($PinnedGuid) {
        if ([guid]$vpn.InterfaceGuid -ne [guid]$PinnedGuid) { throw 'Internet traffic no longer uses the saved VPN. Reconnect it or explicitly reselect the VPN.' }
    } elseif ($vpn.InterfaceDescription -notmatch '(?i)WireGuard|Wintun|TAP-Windows|OpenVPN|AnyConnect|NordLynx|WAN Miniport \((IKEv2|SSTP|PPTP|L2TP)\)') {
        throw 'The internet interface is virtual but its VPN type is not recognized. Select its GUID explicitly after checking your VPN client.'
    }
    $vpn
}
function Get-GuardBlockedAdapters($Vpn) {
    @(Get-GuardNetworkAdapters | Where-Object { [guid]$_.InterfaceGuid -ne [guid]$Vpn.InterfaceGuid })
}
function Assert-GuardNoProxy {
    foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')) {
        if ([Environment]::GetEnvironmentVariable($name)) { throw 'A proxy environment variable is configured. Guard requires direct traffic through a VPN adapter.' }
    }
    $settings=Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction Stop
    if ($settings.ProxyEnable -eq 1 -or $settings.AutoConfigURL) { throw 'A Windows proxy/PAC is configured. Disable it or use a full-tunnel VPN adapter.' }
    # Proxy auto-discovery is disabled in the bound location request as well.
}
function Get-GuardVpnSourceAddress($Vpn) {
    # A bound source must not be sent through a different interface in weak-host mode.
    $interfaces=@(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop)
    if (@($interfaces | Where-Object { $_.InterfaceIndex -ne $Vpn.ifIndex -and "$($_.WeakHostSend)" -ne 'Disabled' }).Count) { throw 'Weak-host sending is enabled outside the VPN. Bound location checks are unsafe on this configuration.' }
    $addresses=@(Get-NetIPAddress -InterfaceIndex $Vpn.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Where-Object {
        "$($_.AddressState)" -eq 'Preferred' -and -not $_.SkipAsSource -and $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1'
    })
    if (-not $addresses.Count) { throw 'The VPN has no usable IPv4 source address.' }
    [string]$addresses[0].IPAddress
}
function Invoke-GuardBoundLocationRequest([string]$Uri,[string]$SourceAddress,[int]$InterfaceIndex) {
    if ($InterfaceIndex -le 0) { throw 'The location request requires a verified VPN interface index.' }
    if (-not ('ClaudeGuard.BoundRequest' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Net;
using System.IO;
using System.Runtime.InteropServices;
namespace ClaudeGuard {
    public static class BoundRequest {
        [DllImport("iphlpapi.dll")] static extern uint GetBestInterfaceEx(byte[] address, out uint index);
        public static string Get(string uri, string source, int index) {
            IPAddress address = IPAddress.Parse(source);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            var request = (HttpWebRequest)WebRequest.Create(uri);
            request.Proxy = null;
            request.AllowAutoRedirect = false;
            request.Timeout = 4000; request.ReadWriteTimeout = 4000;
            request.UserAgent = "ClaudeVPNGuard/1.4";
            request.ConnectionGroupName = Guid.NewGuid().ToString();
            request.ServicePoint.BindIPEndPointDelegate = delegate(ServicePoint service, IPEndPoint remote, int retry) {
                if (remote.AddressFamily != address.AddressFamily || retry > 0) throw new InvalidOperationException("VPN source binding failed.");
                byte[] socketAddress = new byte[16]; socketAddress[0] = 2;
                Buffer.BlockCopy(remote.Address.GetAddressBytes(), 0, socketAddress, 4, 4);
                uint selected;
                if (GetBestInterfaceEx(socketAddress, out selected) != 0 || selected != index) throw new InvalidOperationException("Location endpoint route is outside the VPN.");
                return new IPEndPoint(address, 0);
            };
            try {
                using (var response = (HttpWebResponse)request.GetResponse()) {
                    if (response.StatusCode != HttpStatusCode.OK) throw new InvalidOperationException("Location endpoint refused the request.");
                    using (var reader = new StreamReader(response.GetResponseStream())) {
                        char[] buffer = new char[65537];
                        int count = reader.ReadBlock(buffer, 0, buffer.Length);
                        if (count > 65536) throw new InvalidOperationException("Location response is too large.");
                        return new string(buffer, 0, count);
                    }
                }
            } finally { request.ServicePoint.CloseConnectionGroup(request.ConnectionGroupName); }
        }
    }
}
'@
    }
    [ClaudeGuard.BoundRequest]::Get($Uri,$SourceAddress,$InterfaceIndex) | ConvertFrom-Json -ErrorAction Stop
}
function New-GuardChangeMonitor($Inventory) {
    if (-not ('ClaudeGuard.ChangeMonitor' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Net.NetworkInformation;
using System.Threading;
namespace ClaudeGuard {
    public sealed class ChangeMonitor : IDisposable {
        int changed;
        readonly List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
        void AddressChanged(object sender, EventArgs args) { Interlocked.Exchange(ref changed, 1); }
        void AvailabilityChanged(object sender, NetworkAvailabilityEventArgs args) { Interlocked.Exchange(ref changed, 1); }
        public ChangeMonitor(string[] directories) {
            NetworkChange.NetworkAddressChanged += AddressChanged;
            NetworkChange.NetworkAvailabilityChanged += AvailabilityChanged;
            foreach (string directory in directories) {
                try {
                    if (!Directory.Exists(directory)) continue;
                    var watcher = new FileSystemWatcher(directory, "*.exe");
                    watcher.IncludeSubdirectories = true;
                    watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite;
                    watcher.Created += (s, e) => Interlocked.Exchange(ref changed, 1);
                    watcher.Changed += (s, e) => Interlocked.Exchange(ref changed, 1);
                    watcher.Deleted += (s, e) => Interlocked.Exchange(ref changed, 1);
                    watcher.Renamed += (s, e) => Interlocked.Exchange(ref changed, 1);
                    watcher.Error += (s, e) => Interlocked.Exchange(ref changed, 1);
                    watchers.Add(watcher); watcher.EnableRaisingEvents = true;
                } catch { /* Periodic full verification remains mandatory. */ }
            }
        }
        public bool Consume() { return Interlocked.Exchange(ref changed, 0) != 0; }
        public void Dispose() {
            NetworkChange.NetworkAddressChanged -= AddressChanged;
            NetworkChange.NetworkAvailabilityChanged -= AvailabilityChanged;
            foreach (var watcher in watchers) watcher.Dispose();
        }
    }
}
'@
    }
    $directories=@($Inventory.Programs | ForEach-Object {
        $directory=Split-Path $_ -Parent
        if ((Split-Path $directory -Leaf) -like 'app-*') { Split-Path $directory -Parent } else { $directory }
    } | Sort-Object -Unique)
    New-Object ClaudeGuard.ChangeMonitor (,[string[]]$directories)
}
