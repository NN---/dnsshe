using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshConnector : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshConnector() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_connector_free(handle);
            return true;
        }
    }
}
