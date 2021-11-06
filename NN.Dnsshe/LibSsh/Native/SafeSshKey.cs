using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    public class SafeSshKey : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshKey() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_key_free(handle);
            return true;
        }
    }
}
