using System.Diagnostics.CodeAnalysis;

using NN.Dnsshe.LibSsh.Native;

using NUnit.Framework;

namespace NN.Dnsshe.Tests.LibSsh.Native
{
    /// <summary>
    /// The purpose of this test is just to make sure the methods signature is correct.
    /// </summary>
    [SuppressMessage("ReSharper", "NotAccessedVariable")]
    public class AvailabilityTests
    {
        [Test][Category("Availability")][Category("System")][Explicit]
        public void SshConnect()
        {
            using var ssh = NativeMethods.ssh_new();

            var errInt = NativeMethods.ssh_options_set(ssh, ssh_options_e.SSH_OPTIONS_HOST, "ssh.blinkenshell.org");
            Assert.Zero(errInt);
            errInt = NativeMethods.ssh_options_set(ssh, ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY, ssh_log_e.SSH_LOG_PROTOCOL);
            Assert.Zero(errInt);
            errInt = NativeMethods.ssh_options_set(ssh, ssh_options_e.SSH_OPTIONS_PORT, 2222);
            Assert.Zero(errInt);

            var err = NativeMethods.ssh_connect(ssh);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            var errAuth = NativeMethods.ssh_userauth_password(ssh, "signup", "signup23");
            Assert.AreEqual(ssh_auth_e.SSH_AUTH_SUCCESS, errAuth);

            NativeMethods.ssh_disconnect(ssh);
            NativeMethods.ssh_silent_disconnect(ssh);

            NativeMethods.ssh_free(ssh.DangerousGetHandle());

            // Prevent double free
            ssh.SetHandleAsInvalid();
        }
    }
}
