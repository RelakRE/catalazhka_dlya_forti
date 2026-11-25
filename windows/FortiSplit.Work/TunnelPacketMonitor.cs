using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace FortiSplit.Work;

internal sealed class TunnelPacketMonitor : IDisposable
{
    private const uint ApiVersion = 0x00010000;
    private const int NetworkInterfaceSource = 1;
    internal const ushort EthernetPayload = 1;
    internal const ushort IpPayload = 3;
    internal const ushort ReceiveDirection = 3;
    internal const ushort SendDirection = 4;
    private const uint SourceHasGuid = 1;
    private const ushort CaptureBytes = 96;

    private readonly PacketCallback packetCallback;
    private readonly StreamCallback streamCallback;
    private nint driver;
    private nint session;
    private nint stream;
    private volatile bool running;

    private TunnelPacketMonitor(uint address, TunnelActivity.RecentPeers recent)
    {
        packetCallback = (nint _, in PacketData data) => ObservePacket(data, address, recent);
        streamCallback = (_, _, kind) =>
        {
            if (kind is StreamEvent.Stopped or StreamEvent.FatalError) running = false;
        };
    }

    internal bool IsRunning => running;

    [SupportedOSPlatform("windows")]
    internal static TunnelPacketMonitor? Start(Guid adapterId, uint address, TunnelActivity.RecentPeers recent)
    {
        var monitor = new TunnelPacketMonitor(address, recent);
        bool started = false;
        try
        {
            started = monitor.Open(adapterId, recent);
            return started ? monitor : null;
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
            return null;
        }
        finally
        {
            if (!started) monitor.Dispose();
        }
    }

    private bool Open(Guid adapterId, TunnelActivity.RecentPeers recent)
    {
        if (PacketMonitorInitialize(ApiVersion, 0, out driver) < 0 ||
            PacketMonitorCreateLiveSession(driver, $"FortiSplitWork-{Environment.ProcessId}", out session) < 0 ||
            !AddAdapter(adapterId)) return false;

        var settings = new StreamConfiguration
        {
            DataCallback = Marshal.GetFunctionPointerForDelegate(packetCallback),
            EventCallback = Marshal.GetFunctionPointerForDelegate(streamCallback),
            BufferSizeMultiplier = 4,
            TruncationSize = CaptureBytes
        };
        if (PacketMonitorCreateRealtimeStream(driver, in settings, out stream) < 0 ||
            PacketMonitorAttachOutputToSession(session, stream) < 0) return false;

        recent.Restart(Stopwatch.GetTimestamp());
        running = true;
        return PacketMonitorSetSessionActive(session, 1) >= 0;
    }

    private unsafe bool AddAdapter(Guid adapterId)
    {
        const int pointerTableOffset = sizeof(long); // UINT32 count followed by aligned pointers on Windows x64.
        PacketMonitorEnumDataSources(driver, NetworkInterfaceSource, 0, 0, out nuint needed, 0);
        if (needed < pointerTableOffset || needed > int.MaxValue) return false;

        nint buffer = Marshal.AllocHGlobal((int)needed);
        try
        {
            if (PacketMonitorEnumDataSources(driver, NetworkInterfaceSource, 0, needed, out _, buffer) < 0) return false;
            uint count = *(uint*)buffer;
            if (count > (needed - pointerTableOffset) / (nuint)IntPtr.Size) return false;

            var sources = (AdapterSource**)(buffer + pointerTableOffset);
            for (int index = 0; index < count; index++)
            {
                var source = sources[index];
                if (source == null || (source->DetailsPresent & SourceHasGuid) == 0 || source->Guid != adapterId) continue;
                return PacketMonitorAddSingleDataSourceToSession(session, (nint)source) >= 0;
            }
            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static unsafe void ObservePacket(in PacketData data, uint address, TunnelActivity.RecentPeers recent)
    {
        if (data.Buffer == 0 || data.DataSize < sizeof(PacketMetadata) ||
            data.MetadataOffset > data.DataSize - sizeof(PacketMetadata) || data.PacketOffset >= data.DataSize) return;
        var metadata = (PacketMetadata*)(data.Buffer + (nint)data.MetadataOffset);
        if (metadata->DropReason != 0) return;

        int length = (int)Math.Min(CaptureBytes, Math.Min(data.PacketLength, data.DataSize - data.PacketOffset));
        var frame = new ReadOnlySpan<byte>((void*)(data.Buffer + (nint)data.PacketOffset), length);
        if (ReadFrame(frame, address, metadata->PacketType, metadata->Direction) is { } packet)
            recent.Observe(packet, Stopwatch.GetTimestamp());
    }

    internal static TunnelActivity.Packet? ReadFrame(ReadOnlySpan<byte> frame, uint address, ushort packetType, ushort direction)
    {
        // Network-interface Rx/Tx events count the packet once at the adapter boundary.
        if (direction is not (ReceiveDirection or SendDirection)) return null;
        if (packetType == EthernetPayload)
        {
            int headerLength = 14;
            while (frame.Length >= headerLength)
            {
                ushort protocol = BinaryPrimitives.ReadUInt16BigEndian(frame[(headerLength - 2)..]);
                if (protocol == 0x0800) break;
                if (protocol is not (0x8100 or 0x88a8)) return null;
                headerLength += 4;
            }
            if (frame.Length < headerLength) return null;
            frame = frame[headerLength..];
        }
        else if (packetType != IpPayload) return null;

        var packet = TunnelActivity.ReadPacket(frame, address);
        return packet is { } item && item.Incoming == (direction == ReceiveDirection) ? item : null;
    }

    public void Dispose()
    {
        running = false;
        if (stream != 0) PacketMonitorCloseRealtimeStream(stream);
        if (session != 0) PacketMonitorCloseSessionHandle(session);
        if (driver != 0) PacketMonitorUninitialize(driver);
        stream = session = driver = 0;
        GC.KeepAlive(this); // Native code can call the delegates until the stream closes.
    }

    // PACKETMONITOR_DATA_SOURCE_SPECIFICATION uses WCHAR[64], WCHAR[128] and an 8-byte-aligned detail union.
    [StructLayout(LayoutKind.Explicit)]
    private struct AdapterSource
    {
        [FieldOffset(400)] internal uint DetailsPresent;
        [FieldOffset(408)] internal Guid Guid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StreamConfiguration
    {
        internal nint UserContext;
        internal nint EventCallback;
        internal nint DataCallback;
        internal ushort BufferSizeMultiplier;
        internal ushort TruncationSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PacketData
    {
        internal nint Buffer;
        internal uint DataSize;
        internal uint MetadataOffset;
        internal uint PacketOffset;
        internal uint PacketLength;
        internal uint MissedPacketWriteCount;
        internal uint MissedPacketReadCount;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct PacketMetadata
    {
        [FieldOffset(12)] internal ushort Direction;
        [FieldOffset(14)] internal ushort PacketType;
        [FieldOffset(24)] internal uint DropReason;
    }

    private enum StreamEvent { Started, Stopped, FatalError, ProcessInfo }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void PacketCallback(nint context, in PacketData data);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void StreamCallback(nint context, nint info, StreamEvent kind);

    private const string Library = "pktmonapi.dll";

    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int PacketMonitorInitialize(uint apiVersion, nint reserved, out nint handle);
    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void PacketMonitorUninitialize(nint handle);
    [DllImport(Library, ExactSpelling = true, CharSet = CharSet.Unicode), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int PacketMonitorCreateLiveSession(nint handle, string name, out nint session);
    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void PacketMonitorCloseSessionHandle(nint session);
    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int PacketMonitorEnumDataSources(nint handle, int kind, byte showHidden, nuint capacity, out nuint needed, nint buffer);
    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int PacketMonitorAddSingleDataSourceToSession(nint session, nint source);
    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int PacketMonitorCreateRealtimeStream(nint handle, in StreamConfiguration configuration, out nint stream);
    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void PacketMonitorCloseRealtimeStream(nint stream);
    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int PacketMonitorAttachOutputToSession(nint session, nint stream);
    [DllImport(Library, ExactSpelling = true), DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int PacketMonitorSetSessionActive(nint session, byte active);
}
