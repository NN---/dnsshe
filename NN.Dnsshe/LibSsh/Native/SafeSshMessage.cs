using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshMessage : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshMessage() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_message_free(handle);
            return true;
        }
    }
}
