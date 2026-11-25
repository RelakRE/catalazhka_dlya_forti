using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;

namespace FortiSplit.Work;

internal static class TunnelActivity
{
    internal const int RecentSeconds = 5;
    internal const int HistoryLimit = 5;

    [SupportedOSPlatform("windows")]
    internal static TunnelPacketMonitor? Start(WorkNetwork network, RecentPeers recent)
    {
        try
        {
            if (!Guid.TryParse(network.Guid, out var adapterId) || network.TunnelAddress() is not { } address) return null;
            return TunnelPacketMonitor.Start(adapterId, AddressKey(address), recent);
        }
        catch (NetworkInformationException)
        {
            return null;
        }
    }

    internal static uint AddressKey(IPAddress address) => BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes());

    internal readonly record struct Packet(uint Address, bool Incoming, int Length);

    internal static Packet? ReadPacket(ReadOnlySpan<byte> packet, uint local)
    {
        if (packet.Length < 20 || packet[0] >> 4 != 4) return null;
        int headerLength = (packet[0] & 15) * 4;
        int length = BinaryPrimitives.ReadUInt16BigEndian(packet[2..]);
        // Packet Monitor can deliver only the header. The IPv4 length includes the payload on the wire.
        if (headerLength < 20 || length < headerLength || packet.Length < headerLength) return null;
        uint source = BinaryPrimitives.ReadUInt32BigEndian(packet[12..]);
        uint destination = BinaryPrimitives.ReadUInt32BigEndian(packet[16..]);
        if (source == destination) return null;
        if (source == local) return new(destination, Incoming: false, length);
        return destination == local ? new(source, Incoming: true, length) : null;
    }

    internal sealed class RecentPeers
    {
        private readonly object gate = new();
        private Dictionary<uint, Observation> observations = [];
        private readonly List<(long LastSeen, WorkActivityEvent Event)> history = [];
        private long? previousTimestamp;

        private sealed class Observation(WorkPeer peer)
        {
            internal WorkPeer Peer = peer;
            internal long? LastSeen;
            internal long Started;
            internal DateTimeOffset StartedUtc;
            internal long Received;
            internal long Sent;
            internal long PreviousReceived;
            internal long PreviousSent;

            internal void SetBaseline()
            {
                PreviousReceived = Received;
                PreviousSent = Sent;
            }

            internal WorkActivityInterval Interval(long end)
            {
                var elapsed = Stopwatch.GetElapsedTime(Started, end);
                return new(StartedUtc, StartedUtc + elapsed, elapsed);
            }
        }

        internal void Replace(WorkPeer[] peers)
        {
            lock (gate)
            {
                var updated = new Dictionary<uint, Observation>();
                foreach (var peer in peers)
                {
                    uint address = AddressKey(IPAddress.Parse(peer.Address));
                    var observation = observations.GetValueOrDefault(address) ?? new Observation(peer);
                    observation.Peer = peer;
                    updated[address] = observation;
                }
                foreach (var (address, observation) in observations)
                    if (!updated.ContainsKey(address)) Archive(observation);
                observations = updated;
            }
        }

        internal void Restart(long timestamp)
        {
            lock (gate)
            {
                previousTimestamp = timestamp;
                foreach (var observation in observations.Values)
                {
                    Archive(observation);
                    observation.SetBaseline();
                }
            }
        }

        internal void Observe(Packet packet, long timestamp, DateTimeOffset? utc = null)
        {
            lock (gate)
            {
                if (!observations.TryGetValue(packet.Address, out var observation)) return;
                if (observation.LastSeen is long seen && IsIdle(seen, timestamp)) Archive(observation);
                if (observation.LastSeen is null)
                {
                    observation.Started = timestamp;
                    observation.StartedUtc = utc ?? DateTimeOffset.UtcNow;
                }
                if (packet.Incoming) observation.Received += packet.Length;
                else observation.Sent += packet.Length;
                observation.LastSeen = timestamp;
            }
        }

        internal WorkTrafficSnapshot Snapshot(long? timestamp = null)
        {
            lock (gate)
            {
                long now = timestamp ?? Stopwatch.GetTimestamp();
                double seconds = previousTimestamp is long previous ? Stopwatch.GetElapsedTime(previous, now).TotalSeconds : 0;
                var active = new List<WorkPeerTraffic>();
                foreach (var item in observations.Values)
                {
                    if (item.LastSeen is long seen)
                    {
                        if (IsIdle(seen, now)) Archive(item);
                        else active.Add(new(item.Peer, item.Received, item.Sent,
                            seconds > 0 ? (item.Received - item.PreviousReceived) / seconds : null,
                            seconds > 0 ? (item.Sent - item.PreviousSent) / seconds : null, item.Interval(seen)));
                    }
                    if (seconds > 0 || previousTimestamp is null) item.SetBaseline();
                }
                if (seconds > 0 || previousTimestamp is null) previousTimestamp = now;
                return new(now, [.. active], RecentEvents());
            }
        }

        internal WorkTrafficSnapshot Finish(long? timestamp = null)
        {
            lock (gate)
            {
                foreach (var item in observations.Values) Archive(item);
                return new(timestamp ?? Stopwatch.GetTimestamp(), [], RecentEvents(), CaptureAvailable: false);
            }
        }

        private static bool IsIdle(long seen, long now) => Stopwatch.GetElapsedTime(seen, now).TotalSeconds > RecentSeconds;

        private WorkActivityEvent[] RecentEvents() => history.Select(item => item.Event).ToArray();

        private void Archive(Observation item)
        {
            if (item.LastSeen is not long seen) return;
            var entry = (seen, new WorkActivityEvent(item.Peer, item.Interval(seen)));
            item.LastSeen = null;
            int index = history.FindIndex(previous => seen >= previous.LastSeen);
            if (index < 0) index = history.Count;
            if (index == HistoryLimit) return;
            history.Insert(index, entry);
            if (history.Count > HistoryLimit) history.RemoveAt(HistoryLimit);
        }
    }
}
