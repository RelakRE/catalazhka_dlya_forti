using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using FortiSplit.Work;

internal static class WorkChecks
{
    internal static async Task Run(Action<string, bool> check)
    {
        CheckCapturedTraffic(check);
        CheckActivity(check);
        CheckActivityHistory(check);
        CheckAddressUpdate(check);
        await CheckProbes(check);
    }

    private static void CheckCapturedTraffic(Action<string, bool> check)
    {
        var peer = new WorkPeer("198.51.100.8", ["work.example.com"]);
        var local = IPAddress.Parse("192.0.2.20");
        uint localKey = TunnelActivity.AddressKey(local);
        var activity = new TunnelActivity.RecentPeers();
        activity.Replace([peer]);
        activity.Restart(0);

        byte[] incoming = new byte[96];
        incoming[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(incoming.AsSpan(2), 1200);
        IPAddress.Parse(peer.Address).GetAddressBytes().CopyTo(incoming, 12);
        local.GetAddressBytes().CopyTo(incoming, 16);
        if (TunnelPacketMonitor.ReadFrame(incoming, localKey, TunnelPacketMonitor.IpPayload, TunnelPacketMonitor.ReceiveDirection) is { } received)
            activity.Observe(received, 0);

        byte[] ethernet = new byte[14 + 60];
        BinaryPrimitives.WriteUInt16BigEndian(ethernet.AsSpan(12), 0x0800);
        Span<byte> outgoing = ethernet.AsSpan(14);
        outgoing[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(outgoing[2..], (ushort)outgoing.Length);
        incoming.AsSpan(16, 4).CopyTo(outgoing[12..]);
        incoming.AsSpan(12, 4).CopyTo(outgoing[16..]);
        if (TunnelPacketMonitor.ReadFrame(ethernet, localKey, TunnelPacketMonitor.EthernetPayload, TunnelPacketMonitor.SendDirection) is { } sent)
            activity.Observe(sent, 0);

        check("work_activity_counts_full_ipv4_volume_from_captured_headers",
            activity.Snapshot(Stopwatch.Frequency).Peers is [{ Received: 1200, Sent: 60, ReceiveRate: 1200, SendRate: 60 }]);
        check("work_activity_ignores_non_adapter_and_wrong_direction_events",
            TunnelPacketMonitor.ReadFrame(incoming, localKey, TunnelPacketMonitor.IpPayload, direction: 1) is null &&
            TunnelPacketMonitor.ReadFrame(incoming, localKey, TunnelPacketMonitor.IpPayload, TunnelPacketMonitor.SendDirection) is null);
    }

    private static void CheckActivity(Action<string, bool> check)
    {
        var first = new WorkPeer("192.0.2.10", ["first.example.com"]);
        var secondPeer = new WorkPeer("192.0.2.11", ["second.example.com"]);
        var renamed = first with { Hosts = ["new-name.example.com"] };
        uint firstKey = TunnelActivity.AddressKey(IPAddress.Parse(first.Address));
        uint secondKey = TunnelActivity.AddressKey(IPAddress.Parse(secondPeer.Address));
        long start = Stopwatch.GetTimestamp();
        long second = Stopwatch.Frequency;
        var activity = new TunnelActivity.RecentPeers();
        activity.Replace([first]);
        activity.Restart(start);
        activity.Observe(new(secondKey, true, 400), start);
        check("work_activity_ignores_unconfigured_peer", activity.Snapshot(start).Peers.Length == 0);
        activity.Observe(new(firstKey, true, 1200), start + second / 2);
        activity.Observe(new(firstKey, false, 600), start + second / 2);
        activity.Replace([renamed, secondPeer]);
        long lastSeen = start + second;
        activity.Observe(new(secondKey, false, 400), lastSeen);
        activity.Observe(new(firstKey, true, 200), lastSeen);
        var totals = TrafficOnly(activity.Snapshot(start + 2 * second));
        check("work_activity_counts_bytes_and_rates_per_address_and_direction", totals.SequenceEqual([
            new(renamed, 1400, 600, 700, 300), new(secondPeer, 0, 400, 0, 200)]));
        long boundary = lastSeen + TunnelActivity.RecentSeconds * second;
        check("work_activity_remains_visible_at_five_seconds", TrafficOnly(activity.Snapshot(boundary)).SequenceEqual([
            new(renamed, 1400, 600, 0, 0), new(secondPeer, 0, 400, 0, 0)]));
        check("work_activity_expires_after_five_seconds", activity.Snapshot(boundary + second / 2).Peers.Length == 0);
        long restarted = boundary + second;
        activity.Restart(restarted);
        check("work_activity_restart_clears_old_activity", activity.Snapshot(restarted).Peers.Length == 0);
        activity.Observe(new(firstKey, false, 50), restarted + second / 2);
        check("work_activity_restart_preserves_volume_and_resets_rate", TrafficOnly(activity.Snapshot(restarted + second)).SequenceEqual([
            new(renamed, 1400, 650, 0, 50)]));
        activity.Replace([secondPeer]);
        bool removed = activity.Snapshot(restarted + 2 * second).Peers.Length == 0;
        activity.Replace([first, secondPeer]);
        check("work_activity_drops_removed_ip_and_does_not_restore_old_activity", removed && activity.Snapshot(restarted + 2 * second).Peers.Length == 0);
        activity.Observe(new(firstKey, true, 70), restarted + 2 * second);
        check("work_activity_counts_from_zero_for_readded_address", TrafficOnly(activity.Snapshot(restarted + 3 * second)).SequenceEqual([
            new(first, 70, 0, 70, 0)]));

        static IEnumerable<WorkPeerTraffic> TrafficOnly(WorkTrafficSnapshot snapshot) =>
            snapshot.Peers.Select(peer => peer with { Activity = null });
    }

    private static void CheckActivityHistory(Action<string, bool> check)
    {
        var peer = new WorkPeer("192.0.2.40", ["activity.example.com"]);
        var packet = new TunnelActivity.Packet(TunnelActivity.AddressKey(IPAddress.Parse(peer.Address)), true, 64);
        long second = Stopwatch.Frequency;
        var utc = new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero);
        var activity = new TunnelActivity.RecentPeers();
        activity.Replace([peer]);
        activity.Restart(0);
        activity.Observe(packet, 0, utc);
        activity.Observe(packet, 2 * second, utc.AddSeconds(2));
        var active = activity.Snapshot(3 * second);
        var firstInterval = new WorkActivityInterval(utc, utc.AddSeconds(2), TimeSpan.FromSeconds(2));
        check("work_activity_dates_and_duration_cover_received_packets", active.Peers.Single().Activity == firstInterval && active.RecentEvents is []);
        // No sampling between the old and new bursts. The gap alone must close the first one.
        activity.Observe(packet, 9 * second, utc.AddSeconds(9));
        var separated = activity.Snapshot(9 * second);
        check("work_activity_splits_at_idle_gap_without_a_snapshot", separated.RecentEvents is [{ Activity: var interval }] &&
            interval == firstInterval && separated.Peers.Single().Activity?.StartedUtc == utc.AddSeconds(9));
        for (int i = 2; i <= 7; i++) activity.Observe(packet, i * 9 * second, utc.AddSeconds(i * 9));
        var finished = activity.Finish(64 * second);
        check("work_activity_keeps_only_five_latest_completed_events", !finished.CaptureAvailable && finished.Peers.Length == 0 &&
            finished.RecentEvents!.Select(item => item.Activity.StartedUtc).SequenceEqual(Enumerable.Range(3, 5).Reverse().Select(i => utc.AddSeconds(i * 9))));
        check("work_activity_repeated_finish_does_not_duplicate_history", activity.Finish().RecentEvents!.SequenceEqual(finished.RecentEvents!));
    }

    private static void CheckAddressUpdate(Action<string, bool> check)
    {
        var original = new Config { Server = "https://vpn.example.com", AutoRdp = false, ExtraHosts = ["old.example.com"] };
        var request = new WorkAddressRequest(Guid.NewGuid().ToString("N"), ["new.example.com"], []);
        var steps = new List<string>();
        bool active = true;
        var result = request.ApplyToSession(original, () => active, config =>
        {
            if (config.ExtraHosts.SequenceEqual(request.ExtraHosts)) steps.Add("apply");
            active = false;
        }, () => steps.Add("ready"));
        check("work_update_disconnect_during_setup_never_confirms_or_publishes_ready",
            result is null && steps.SequenceEqual(["apply"]));

        steps.Clear();
        result = request.ApplyToSession(original, () => active, _ => steps.Add("apply"), () => steps.Add("ready"));
        check("work_update_ignores_request_after_disconnect", result is null && steps.Count == 0);

        active = true;
        result = request.ApplyToSession(original, () => active, _ => steps.Add("apply"), () => steps.Add("ready"));
        check("work_update_confirms_only_after_configuration_and_ready",
            result is { Success: true } && result.Id == request.Id && steps.SequenceEqual(["apply", "ready"]));
        result = request.ApplyToSession(original, () => active, _ => { }, () => active = false);
        check("work_update_disconnect_during_readiness_never_confirms", result is null);
    }

    private static async Task CheckProbes(Action<string, bool> check)
    {
        IPAddress source = IPAddress.Parse("192.0.2.20"), destination = IPAddress.Parse("198.51.100.8");
        uint sourceKey = BinaryPrimitives.ReadUInt32LittleEndian(source.GetAddressBytes());
        uint destinationKey = BinaryPrimitives.ReadUInt32LittleEndian(destination.GetAddressBytes());
        const uint vpnIndex = 77;
        const int port = 443;
        var vpnRoute = new WorkConnectionCheck.Route { InterfaceIndex = vpnIndex, Prefix = destinationKey, Mask = uint.MaxValue, NextHop = sourceKey };
        var outsideRoute = new WorkConnectionCheck.Route { InterfaceIndex = 2 };
        int probes = 0, correctlyBound = 0;
        string Ping(uint from, uint to)
        {
            Interlocked.Increment(ref probes);
            if (from == sourceKey && to == destinationKey) Interlocked.Increment(ref correctlyBound);
            return "10 мс";
        }
        Task<string> Tcp(IPAddress from, IPAddress to, uint index, int targetPort, CancellationToken token)
        {
            Interlocked.Increment(ref probes);
            if (from.Equals(source) && to.Equals(destination) && index == vpnIndex && targetPort == port && !token.IsCancellationRequested)
                Interlocked.Increment(ref correctlyBound);
            return Task.FromResult("доступен");
        }
        Task<WorkConnectionResult> Run(Func<uint, uint, WorkConnectionCheck.Route?> route, int? targetPort = port) =>
            WorkConnectionCheck.Run(vpnIndex, destination, targetPort, CancellationToken.None, route, () => source,
                _ => "fixture adapter", Ping, Tcp);

        var report = await Run((_, _) => outsideRoute);
        check("work_diagnostic_outside_vpn_never_sends_probes", report is { Route: "Вне VPN", Ping: null, Tcp: null } && probes == 0);
        report = await Run((_, from) => from == 0 ? vpnRoute : outsideRoute);
        check("work_diagnostic_checks_source_route_before_probing", report.Route == "Маршрут через VPN недоступен" && probes == 0);
        var lookups = new List<(uint Destination, uint Source)>();
        report = await Run((to, from) => { lookups.Add((to, from)); return vpnRoute; });
        check("work_diagnostic_binds_probes_to_vpn_source_and_interface", probes == 2 && correctlyBound == 2 &&
            lookups.SequenceEqual([(destinationKey, 0u), (destinationKey, sourceKey)]) && report.RouteDetails?.Contains("198.51.100.8/32", StringComparison.Ordinal) == true);
        check("work_diagnostic_tunnel_source_is_not_shown_as_a_remote_gateway", report.RouteDetails?.Contains(source.ToString(), StringComparison.Ordinal) == false);
        report = await Run((_, _) => vpnRoute, null);
        check("work_diagnostic_without_service_pings_without_tcp", probes == 3 && report is { Ping: "10 мс", Tcp: null });

        Task<string> CheckTcp(Func<IPAddress, IPAddress, uint, int, CancellationToken, Task> connect,
            TimeSpan limit, CancellationToken token = default) =>
            WorkConnectionCheck.CheckTcp(source, destination, vpnIndex, port, token, connect, limit);

        string refused = await CheckTcp((_, _, _, _, _) => Task.FromException(new SocketException((int)SocketError.ConnectionRefused)),
            Timeout.InfiniteTimeSpan);
        check("work_diagnostic_reports_tcp_refused", refused == "соединение отклонено");
        string timedOut = await CheckTcp((_, _, _, _, token) => Task.Delay(Timeout.InfiniteTimeSpan, token), TimeSpan.FromMilliseconds(20))
            .WaitAsync(TimeSpan.FromSeconds(3));
        check("work_diagnostic_reports_tcp_timeout", timedOut == "истекло время ожидания");

        using var cancellation = new CancellationTokenSource();
        Task<string> inProgress = CheckTcp((_, _, _, _, token) => Task.Delay(Timeout.InfiniteTimeSpan, token),
            Timeout.InfiniteTimeSpan, cancellation.Token);
        cancellation.Cancel();
        bool cancelled = false;
        try { await inProgress.WaitAsync(TimeSpan.FromSeconds(3)); }
        catch (OperationCanceledException) { cancelled = true; }
        check("work_diagnostic_cancellation_is_distinct_from_timeout", cancelled);
    }
}
