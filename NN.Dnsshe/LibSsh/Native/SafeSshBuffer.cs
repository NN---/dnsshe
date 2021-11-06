using System;
using System.Collections.Generic;
using System.Text;

using JetBrains.Annotations;

using Microsoft.Win32.SafeHandles;

namespace NN.Dnsshe.LibSsh.Native
{
    [PublicAPI]
    public class SafeSshBuffer : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeSshBuffer() : base(true) { }

        protected override bool ReleaseHandle()
        {
            NativeMethods.ssh_buffer_free(handle);
            return true;
        }
    }
}
