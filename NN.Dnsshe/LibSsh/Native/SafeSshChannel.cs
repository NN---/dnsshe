using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshChannel : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshChannel() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_channel_free(handle);
            return true;
        }
    }
}
