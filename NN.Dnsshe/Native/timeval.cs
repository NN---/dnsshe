using System.Runtime.InteropServices;

// ReSharper disable BuiltInTypeReferenceStyle
// ReSharper disable InconsistentNaming
// ReSharper disable IdentifierTypo

namespace NN.Dnsshe.Native
{
    using time_t = System.UInt64;
    using suseconds_t = System.Int64;

    [StructLayout(LayoutKind.Sequential)]
    public struct timeval
    {
        public time_t tv_sec;

        public suseconds_t tv_usec;
    }
}
