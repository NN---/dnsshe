using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshPcapFile : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshPcapFile() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_pcap_file_free(handle);
            return true;
        }
    }
}
