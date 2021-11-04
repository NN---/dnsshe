using System;

using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public sealed class SafeSshHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshHandle() : base(true) { }

        public SafeSshHandle(IntPtr handle, bool ownsHandle):
            base(ownsHandle)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_free(handle);
            return true;
        }

        // ReSharper disable once InconsistentNaming
        public static readonly SafeSshHandle SSH_INVALID_SOCKET =
            new((IntPtr)(-1), true);
    }
}
