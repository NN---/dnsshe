using System;

using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public sealed class SafeSshSession : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshSession() : base(true) { }

        public SafeSshSession(IntPtr handle, bool ownsHandle):
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
        public static readonly SafeSshSession SSH_INVALID_SOCKET =
            new((IntPtr)(-1), true);
    }
}
