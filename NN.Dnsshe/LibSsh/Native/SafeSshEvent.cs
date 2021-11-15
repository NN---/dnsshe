using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshEvent : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshEvent() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_event_free(handle);
            return true;
        }
    }
}
