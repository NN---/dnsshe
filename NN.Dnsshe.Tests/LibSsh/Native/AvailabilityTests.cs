using System;
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
        [Test]
        [Category("Availability")]
        [Category("System")]
        [Explicit]
        public void SshConnect()
        {
            using var ssh = NativeMethods.ssh_new();

            var errInt = NativeMethods.ssh_options_set(ssh, ssh_options_e.SSH_OPTIONS_HOST, "ssh.blinkenshell.org");
            Assert.Zero(errInt);
            errInt = NativeMethods.ssh_options_set(
                ssh, ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY, ssh_log_e.SSH_LOG_PROTOCOL);
            Assert.Zero(errInt);
            errInt = NativeMethods.ssh_options_set(ssh, ssh_options_e.SSH_OPTIONS_PORT, 2222);
            Assert.Zero(errInt);

            var err = NativeMethods.ssh_connect(ssh);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            var errAuth = NativeMethods.ssh_userauth_password(ssh, "signup", "signup23");
            Assert.AreEqual(ssh_auth_e.SSH_AUTH_SUCCESS, errAuth);

            err = NativeMethods.ssh_get_server_publickey(ssh, out var srvPubkey);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            NativeMethods.ssh_disconnect(ssh);
            NativeMethods.ssh_silent_disconnect(ssh);
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        [SuppressMessage("ReSharper", "HeuristicUnreachableCode")]
        public void Free()
        {
            Assert.Pass();
            return;

#pragma warning disable CS0162
            NativeMethods.ssh_buffer_free(IntPtr.Zero);
            NativeMethods.ssh_channel_free(IntPtr.Zero);
            NativeMethods.ssh_connector_free(IntPtr.Zero);
            NativeMethods.ssh_event_free(IntPtr.Zero);
            NativeMethods.ssh_free(IntPtr.Zero);
            var knownhostsEntry = new ssh_knownhosts_entry();
            NativeMethods.ssh_knownhosts_entry_free(ref knownhostsEntry);
            NativeMethods.ssh_message_free(IntPtr.Zero);
            NativeMethods.ssh_pcap_file_free(IntPtr.Zero);
            NativeMethods.ssh_scp_free(IntPtr.Zero);
            NativeMethods.ssh_key_free(IntPtr.Zero);
            NativeMethods.ssh_string_free(IntPtr.Zero);
            NativeMethods.ssh_buffer_free(IntPtr.Zero);
            NativeMethods.ssh_clean_pubkey_hash(IntPtr.Zero);
#pragma warning restore CS0162
        }
    }
}
