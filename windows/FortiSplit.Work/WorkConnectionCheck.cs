using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace FortiSplit.Work;

internal sealed record WorkConnectionResult(string Route, string? RouteDetails = null, string? Ping = null,
    string? Tcp = null, string? Notice = null);

internal static class WorkConnectionCheck
{
    private const int TimeoutMilliseconds = 2000;
    private const SocketOptionName UnicastInterface = (SocketOptionName)31; // IP_UNICAST_IF

    // Only the route fields used here are declared (MIB_IPFORWARDROW).
    [StructLayout(LayoutKind.Explicit, Size = 56)]
    internal struct Route
    {
        [FieldOffset(0)] internal uint Prefix;
        [FieldOffset(4)] internal uint Mask;
        [FieldOffset(12)] internal uint NextHop;
        [FieldOffset(16)] internal uint InterfaceIndex;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint GetBestRoute(uint destination, uint source, out Route route);

    private sealed class IcmpHandle : SafeHandleMinusOneIsInvalid
    {
        public IcmpHandle() : base(true) { }
        protected override bool ReleaseHandle() => IcmpCloseHandle(handle);
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern IcmpHandle IcmpCreateFile();

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IcmpCloseHandle(IntPtr handle);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern uint IcmpSendEcho2Ex(IcmpHandle handle, IntPtr completionEvent, IntPtr callback,
        IntPtr context, uint source, uint destination, byte[] request, ushort requestSize, IntPtr options,
        [Out] byte[] reply, uint replySize, uint timeout);

    internal static Task<WorkConnectionResult> Run(WorkNetwork network, IPAddress destination, int? port, CancellationToken cancellation) =>
        Run(network.Index, destination, port, cancellation, FindRoute, network.TunnelAddress, AdapterName,
            MeasureLatency, (source, target, index, targetPort, token) =>
                CheckTcp(source, target, index, targetPort, token, ConnectTcp, TimeSpan.FromMilliseconds(TimeoutMilliseconds)));

    internal static async Task<WorkConnectionResult> Run(uint vpnIndex, IPAddress destination, int? port, CancellationToken cancellation,
        Func<uint, uint, Route?> findRoute, Func<IPAddress?> tunnelAddress, Func<uint, string?> adapterName,
        Func<uint, uint, string> measureLatency, Func<IPAddress, IPAddress, uint, int, CancellationToken, Task<string>> checkTcp)
    {
        cancellation.ThrowIfCancellationRequested();
        uint target = ToNativeAddress(destination);
        if (findRoute(target, 0) is not { } route) return new("Маршрут не найден");

        if (route.InterfaceIndex != vpnIndex)
        {
            return new("Вне VPN", DescribeRoute(route, adapterName(route.InterfaceIndex)),
                Notice: "Пинг и TCP выполняются для адресов с маршрутом через VPN.");
        }

        if (tunnelAddress() is not { } source) return new("VPN-адаптер недоступен");
        uint local = ToNativeAddress(source);
        if (findRoute(target, local) is not { } sourceRoute || sourceRoute.InterfaceIndex != vpnIndex)
            return new("Маршрут через VPN недоступен", Notice: "Windows не выбрала VPN для исходного адреса туннеля.");

        cancellation.ThrowIfCancellationRequested();
        var ping = Task.Run(() => measureLatency(local, target), cancellation);
        var tcp = port is int targetPort ? checkTcp(source, destination, vpnIndex, targetPort, cancellation) : null;
        if (tcp is not null) await Task.WhenAll(ping, tcp).ConfigureAwait(false);
        string latency = await ping.ConfigureAwait(false);
        cancellation.ThrowIfCancellationRequested();
        string? portStatus = tcp is not null ? $"{port} · {await tcp.ConfigureAwait(false)}" : null;
        return new("Через VPN", DescribeRoute(sourceRoute, TunnelTraffic.AdapterName, local), latency, portStatus,
            latency == "нет ответа" ? "Сервер может не отвечать на пинг при доступном сервисе." : null);
    }

    private static string DescribeRoute(Route route, string? adapter, uint local = 0)
    {
        string prefix = $"{new IPAddress(route.Prefix)}/{BitOperations.PopCount(route.Mask)}";
        string nextHop = route.NextHop == 0 || route.NextHop == local ? "" : $" · шлюз {new IPAddress(route.NextHop)}";
        return $"{adapter ?? $"интерфейс {route.InterfaceIndex}"} · {prefix}{nextHop}";
    }

    private static Route? FindRoute(uint destination, uint source) =>
        GetBestRoute(destination, source, out var route) == 0 ? route : null;

    private static string? AdapterName(uint index) => NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(item =>
        item.Supports(NetworkInterfaceComponent.IPv4) && item.GetIPProperties().GetIPv4Properties()?.Index == index)?.Name;

    private static uint ToNativeAddress(IPAddress address) => BinaryPrimitives.ReadUInt32LittleEndian(address.GetAddressBytes());

    private static string MeasureLatency(uint source, uint destination)
    {
        using var handle = IcmpCreateFile();
        if (handle.IsInvalid) return "проверка недоступна";
        byte[] request = new byte[8], reply = new byte[128];
        uint count = IcmpSendEcho2Ex(handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, source, destination,
            request, (ushort)request.Length, IntPtr.Zero, reply, (uint)reply.Length, TimeoutMilliseconds);
        // ICMP_ECHO_REPLY starts with the reply address, status and round-trip time.
        return count > 0 && BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(4)) == 0
            ? $"{BinaryPrimitives.ReadUInt32LittleEndian(reply.AsSpan(8))} мс" : "нет ответа";
    }

    internal static async Task<string> CheckTcp(IPAddress source, IPAddress destination, uint index, int port, CancellationToken cancellation,
        Func<IPAddress, IPAddress, uint, int, CancellationToken, Task> connect, TimeSpan timeLimit)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(timeLimit);
        try
        {
            timeout.Token.ThrowIfCancellationRequested();
            await connect(source, destination, index, port, timeout.Token).ConfigureAwait(false);
            return "доступен";
        }
        catch (OperationCanceledException) when (!cancellation.IsCancellationRequested) { return "истекло время ожидания"; }
        catch (SocketException error) when (error.SocketErrorCode == SocketError.ConnectionRefused) { return "соединение отклонено"; }
        catch (SocketException) { return "подключение не удалось"; }
    }

    private static async Task ConnectTcp(IPAddress source, IPAddress destination, uint index, int port, CancellationToken cancellation)
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        socket.SetSocketOption(SocketOptionLevel.IP, UnicastInterface, IPAddress.HostToNetworkOrder((int)index));
        socket.Bind(new IPEndPoint(source, 0));
        await socket.ConnectAsync(new IPEndPoint(destination, port), cancellation).ConfigureAwait(false);
    }
}
