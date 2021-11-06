using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

using NN.Dnsshe.LibSsh.Native;

using NUnit.Framework;

// The method is obsolete
#pragma warning disable CS0618

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
            using var session = Connect();

            var err = NativeMethods.ssh_get_server_publickey(session, out var key);
            using var keyDispose = key;
            Assert.False(key.IsInvalid);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);
            
            var errInt = NativeMethods.ssh_get_publickey_hash(
                key, ssh_publickey_hash_type.SSH_PUBLICKEY_HASH_SHA1, out var hash, out var hlen);
            using var hashDispose = hash;
            Assert.False(hash.IsInvalid);
            Assert.NotZero(hlen);
            Assert.Zero(errInt);

            _ = NativeMethods.ssh_is_server_known(session);
            _ = NativeMethods.ssh_session_is_known_server(session);

            NativeMethods.ssh_disconnect(session);
            NativeMethods.ssh_silent_disconnect(session);
        }

        [Test]
        [Category("Availability")]
        [Category("System")]
        [Explicit]
        public void SshChannel()
        {
            using var session = Connect();

            using var channel = NativeMethods.ssh_channel_new(session);
            Assert.NotNull(channel);
            Assert.False(channel.IsInvalid);

            var err = NativeMethods.ssh_channel_open_session(channel);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            err = NativeMethods.ssh_channel_request_exec(channel, "\r");
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            var buf = new byte[1];
            _ = NativeMethods.ssh_channel_read(channel, buf, (uint)buf.Length, false);
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        public void Key()
        {
            using var key = NativeMethods.ssh_key_new();
            Assert.False(key.IsInvalid);
            Assert.NotNull(key);

            Assert.AreEqual(ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, NativeMethods.ssh_key_type(key));
            Assert.AreEqual(ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, NativeMethods.ssh_key_type_from_name(null));

            Assert.True(NativeMethods.ssh_key_cmp(key, key, ssh_keycmp_e.SSH_KEY_CMP_PUBLIC));
            Assert.False(NativeMethods.ssh_key_is_public(key));
            Assert.False(NativeMethods.ssh_key_is_private(key));

            var keyType = NativeMethods.ssh_key_type_to_char(ssh_keytypes_e.SSH_KEYTYPE_ED25519);
            Assert.AreNotEqual(IntPtr.Zero, keyType);

            var keyTypeName = Marshal.PtrToStringAnsi(keyType);
            NAssert.NotNull(keyTypeName);
            Assert.AreEqual(ssh_keytypes_e.SSH_KEYTYPE_ED25519, NativeMethods.ssh_key_type_from_name(keyTypeName));

            var keyTypeUnknown = NativeMethods.ssh_key_type_to_char(ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN);
            Assert.AreEqual(IntPtr.Zero, keyTypeUnknown);
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

        private static SafeSshSession Connect()
        {
            var session = NativeMethods.ssh_new();

            var errInt = NativeMethods.ssh_options_set(session, ssh_options_e.SSH_OPTIONS_HOST, "ssh.blinkenshell.org");
            Assert.Zero(errInt);
            errInt = NativeMethods.ssh_options_set(session, ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY, ssh_log_e.SSH_LOG_PROTOCOL);
            Assert.Zero(errInt);

            errInt = NativeMethods.ssh_options_set(session, ssh_options_e.SSH_OPTIONS_PORT, 2222);
            Assert.Zero(errInt);

            var err = NativeMethods.ssh_connect(session);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            var errAuth = NativeMethods.ssh_userauth_password(session, "signup", "signup23");
            Assert.AreEqual(ssh_auth_e.SSH_AUTH_SUCCESS, errAuth);
            return session;
        }
    }
}
