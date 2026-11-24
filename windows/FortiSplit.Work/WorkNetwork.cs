using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json.Serialization;

namespace FortiSplit.Work;

public sealed record WorkPeer(string Address, string[] Hosts)
{
    [JsonIgnore]
    public string Display => Hosts.Length == 0 ? Address : $"{Address} · {string.Join(", ", Hosts)}";
}

public sealed record WorkActivityInterval(DateTimeOffset StartedUtc, DateTimeOffset LastActivityUtc, TimeSpan Duration);

public sealed record WorkPeerTraffic(WorkPeer Peer, long Received, long Sent, double? ReceiveRate, double? SendRate, WorkActivityInterval? Activity = null);

public sealed record WorkActivityEvent(WorkPeer Peer, WorkActivityInterval Activity);

public sealed record WorkTrafficSnapshot(long Timestamp, WorkPeerTraffic[] Peers, WorkActivityEvent[]? RecentEvents = null, bool CaptureAvailable = true);

internal sealed record ResolvedWorkHost(string Host, string[] Addresses);

internal sealed record WorkNetwork(string Guid, uint Index, string Address, string Stage, ResolvedWorkHost[]? Resolved)
{
    internal IPAddress? TunnelAddress()
    {
        if (!System.Guid.TryParse(Guid, out var id) || !IPAddress.TryParse(Address, out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork) return null;
        if (TunnelTraffic.FindAdapter(id) is not { OperationalStatus: OperationalStatus.Up } adapter) return null;
        var properties = adapter.GetIPProperties();
        return properties.GetIPv4Properties()?.Index == Index &&
            properties.UnicastAddresses.Any(item => item.Address.Equals(address)) ? address : null;
    }

    internal WorkPeer[] Peers() => (Resolved ?? [])
        .SelectMany(host => host.Addresses.Select(address => (Address: address, host.Host)))
        .Where(entry => IPAddress.TryParse(entry.Address, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork)
        .GroupBy(entry => entry.Address, StringComparer.Ordinal)
        .OrderBy(group => group.Key, StringComparer.Ordinal)
        .Select(group => new WorkPeer(group.Key, group.Select(entry => entry.Host)
            .Where(host => !host.Equals(group.Key, StringComparison.Ordinal)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray()))
        .ToArray();
}
