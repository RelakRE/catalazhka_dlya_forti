using System.Diagnostics;
using System.Net.NetworkInformation;

namespace FortiSplit.Work;

internal static class TunnelTraffic
{
    internal const string AdapterName = "FortiSplitWork";

    internal static TunnelCounters? Read(Guid? adapterId = null)
    {
        try
        {
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (!string.Equals(adapter.Name, AdapterName, StringComparison.OrdinalIgnoreCase) ||
                    !Guid.TryParse(adapter.Id, out var id) ||
                    (adapterId.HasValue && adapterId.Value != id))
                    continue;

                var stats = adapter.GetIPStatistics();
                long received = stats.BytesReceived;
                long sent = stats.BytesSent;
                return received >= 0 && sent >= 0 ? new(id, received, sent) : null;
            }
        }
        catch (NetworkInformationException)
        {
            // The adapter can disappear between enumeration and the counter read.
        }
        return null;
    }
}

internal sealed record TrafficSample(long Received, long Sent, double? ReceiveRate, double? SendRate);

internal sealed class SessionTraffic
{
    private TunnelCounters? previous;
    private long? previousTimestamp;
    private long received;
    private long sent;

    internal void Pause() => previousTimestamp = null;

    internal TrafficSample Measure(TunnelCounters start, TunnelCounters current, long timestamp)
    {
        bool sameAdapter = previous?.AdapterId == current.AdapterId;
        var reference = sameAdapter ? previous! : start;
        long receivedDelta = current.Received - reference.Received;
        long sentDelta = current.Sent - reference.Sent;

        // An adapter reset can restart its counters within the same VPN session.
        received += receivedDelta >= 0 ? receivedDelta : current.Received;
        sent += sentDelta >= 0 ? sentDelta : current.Sent;

        double seconds = sameAdapter && previousTimestamp is long last
            ? Stopwatch.GetElapsedTime(last, timestamp).TotalSeconds : 0;
        previous = current;
        previousTimestamp = timestamp;

        return new(received, sent,
            seconds > 0 && receivedDelta >= 0 ? receivedDelta / seconds : null,
            seconds > 0 && sentDelta >= 0 ? sentDelta / seconds : null);
    }
}
