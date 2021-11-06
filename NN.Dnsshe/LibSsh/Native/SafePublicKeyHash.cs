using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafePublicKeyHash : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafePublicKeyHash() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_clean_pubkey_hash(handle);
            return true;
        }
    }
}
