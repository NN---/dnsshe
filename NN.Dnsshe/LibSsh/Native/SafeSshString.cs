using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshString : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshString() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_string_free(handle);
            return true;
        }
    }
}
