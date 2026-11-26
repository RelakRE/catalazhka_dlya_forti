using System;
using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

// Loaded by Windows PowerShell 5.1 from the protected network script directory.
public static class FortiSplitNetworkGuard
{
    private const uint RpcAuthnWinnt = 10;
    private const uint FilterNotFound = 0x80320003;
    private const uint Persistent = 1;
    private const uint Block = 0x1001;
    private const uint UInt32 = 3;
    private const uint ByteArray16 = 11;
    private const uint NotEqual = 10;
    private static readonly Guid OutboundIpv4 = new Guid("1e5c9fae-8a84-4135-a331-950b54229ecd");
    private static readonly Guid OutboundIpv6 = new Guid("a3b3ab6b-3564-488c-9117-f34e82142763");
    private static readonly Guid Universal = new Guid("eebecc03-ced4-4380-819a-2734397b2b74");
    private static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
    private static readonly Guid InterfaceIndex = new Guid("667fd755-d695-434a-8af5-d3835a1259bc");

    // SDK types FWPM_FILTER0 and FWPM_FILTER_CONDITION0, Windows x64.
    [StructLayout(LayoutKind.Sequential)]
    private struct Value { internal uint Type; internal ulong Data; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Condition { internal Guid Field; internal uint Match; internal Value Value; }

    [StructLayout(LayoutKind.Sequential)]
    private struct Action { internal uint Type; internal Guid Key; }

    [StructLayout(LayoutKind.Explicit)]
    private struct Context
    {
        [FieldOffset(0)] internal ulong Raw;
        [FieldOffset(0)] internal Guid Provider;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Filter
    {
        internal Guid Key;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Name;
        internal IntPtr Description;
        internal uint Flags;
        internal IntPtr ProviderKey;
        internal uint ProviderDataSize;
        internal IntPtr ProviderData;
        internal Guid Layer;
        internal Guid Sublayer;
        internal Value Weight;
        internal uint ConditionCount;
        internal IntPtr Conditions;
        internal Action Action;
        internal Context Context;
        internal IntPtr Reserved;
        internal ulong Id;
        internal Value EffectiveWeight;
    }

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmEngineOpen0(IntPtr server, uint authentication, IntPtr identity, IntPtr session, out IntPtr engine);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmEngineClose0(IntPtr engine);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmTransactionBegin0(IntPtr engine, uint flags);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmTransactionCommit0(IntPtr engine);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmTransactionAbort0(IntPtr engine);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmFilterAdd0(IntPtr engine, ref Filter filter, IntPtr securityDescriptor, IntPtr id);
    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    private static extern uint FwpmFilterDeleteByKey0(IntPtr engine, ref Guid key);

    public static bool LayoutIsSupported()
    {
        return IntPtr.Size == 8 && Marshal.SizeOf(typeof(Filter)) == 200 &&
            Marshal.OffsetOf(typeof(Filter), "Conditions").ToInt64() == 120 &&
            Marshal.OffsetOf(typeof(Filter), "Context").ToInt64() == 152 && Marshal.SizeOf(typeof(Condition)) == 40;
    }

    public static void Replace(Guid session, uint tunnelIndex, string[] journaled, string[] desired)
    {
        if (!LayoutIsSupported() || (desired.Length != 0 && tunnelIndex == 0))
            throw new InvalidOperationException("Invalid Windows Filtering Platform configuration.");
        IntPtr engine;
        Check(FwpmEngineOpen0(IntPtr.Zero, RpcAuthnWinnt, IntPtr.Zero, IntPtr.Zero, out engine));
        try
        {
            Check(FwpmTransactionBegin0(engine, 0));
            try
            {
                foreach (string address in journaled)
                {
                    Guid key = FilterKey(session, AddressBytes(address));
                    uint result = FwpmFilterDeleteByKey0(engine, ref key);
                    if (result != FilterNotFound) Check(result);
                }
                foreach (string address in desired) AddFilter(engine, session, tunnelIndex, AddressBytes(address));
                Check(FwpmTransactionCommit0(engine));
            }
            catch
            {
                FwpmTransactionAbort0(engine);
                throw;
            }
        }
        finally { FwpmEngineClose0(engine); }
    }

    private static byte[] AddressBytes(string address)
    {
        return IPAddress.Parse(address).GetAddressBytes();
    }

    private static Guid FilterKey(Guid session, byte[] address)
    {
        byte[] input = new byte[16 + address.Length];
        session.ToByteArray().CopyTo(input, 0);
        address.CopyTo(input, 16);
        using (SHA256 sha = SHA256.Create())
        {
            byte[] key = new byte[16];
            Array.Copy(sha.ComputeHash(input), key, key.Length);
            return new Guid(key);
        }
    }

    private static void AddFilter(IntPtr engine, Guid session, uint tunnelIndex, byte[] address)
    {
        bool ipv6 = address.Length == 16;
        int size = Marshal.SizeOf(typeof(Condition));
        int conditionCount = ipv6 ? 1 : 2;
        IntPtr conditions = Marshal.AllocHGlobal(conditionCount * size + (ipv6 ? address.Length : 0));
        try
        {
            Value remote;
            if (ipv6)
            {
                // The IPv4-only VPN cannot carry these destinations on any interface.
                IntPtr bytes = IntPtr.Add(conditions, size);
                Marshal.Copy(address, 0, bytes, address.Length);
                remote = new Value { Type = ByteArray16, Data = unchecked((ulong)bytes.ToInt64()) };
            }
            else
            {
                // WFP expects the first IPv4 octet in the high byte of the UINT32.
                uint ipv4 = (uint)address[0] << 24 | (uint)address[1] << 16 | (uint)address[2] << 8 | address[3];
                remote = new Value { Type = UInt32, Data = ipv4 };
                Marshal.StructureToPtr(new Condition { Field = InterfaceIndex, Match = NotEqual, Value = new Value { Type = UInt32, Data = tunnelIndex } }, IntPtr.Add(conditions, size), false);
            }
            Marshal.StructureToPtr(new Condition { Field = RemoteAddress, Value = remote }, conditions, false);
            var filter = new Filter
            {
                Key = FilterKey(session, address), Name = "Forti Split work address protection",
                Flags = Persistent, Layer = ipv6 ? OutboundIpv6 : OutboundIpv4, Sublayer = Universal,
                ConditionCount = (uint)conditionCount, Conditions = conditions, Action = new Action { Type = Block }
            };
            Check(FwpmFilterAdd0(engine, ref filter, IntPtr.Zero, IntPtr.Zero));
        }
        finally { Marshal.FreeHGlobal(conditions); }
    }

    private static void Check(uint result)
    {
        if (result != 0) throw new Win32Exception(unchecked((int)result), "Windows Filtering Platform error 0x" + result.ToString("X8"));
    }
}
