using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshChar : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshChar() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_string_free_char(handle);
            return true;
        }
    }
}
