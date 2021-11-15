using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshScp : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshScp() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_scp_free(handle);
            return true;
        }
    }
}
