using System;
using System.Runtime.InteropServices;

using NN.Dnsshe.LibSsh.Native;

using NUnit.Framework;
// ReSharper disable HeuristicUnreachableCode
// ReSharper disable RedundantAssignment
// ReSharper disable UnusedVariable
// ReSharper disable SuggestVarOrType_SimpleTypes
// ReSharper disable SuggestVarOrType_BuiltInTypes
// Using explicit types on purpose


// Use 'var'
#pragma warning disable IDE0007

// The method is obsolete
#pragma warning disable CS0618

// Unreachable code detected
#pragma warning disable CS0162

namespace NN.Dnsshe.Tests.LibSsh.Native
{
    /// <summary>
    /// The purpose of this test is just to make sure the methods signature is correct.
    /// </summary>
    [Parallelizable(ParallelScope.All)]
    public class AvailabilityTests
    {
        [Test]
        [Category("Availability")]
        [Category("System")]
        [Explicit]
        public void SshConnect()
        {
            using SafeSshSession session = Connect();

            ssh_error_e err = NativeMethods.ssh_get_server_publickey(session, out SafeSshKey key);
            using SafeSshKey keyDispose = key;
            Assert.False(key.IsInvalid);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            int errInt = NativeMethods.ssh_get_publickey_hash(
                key, ssh_publickey_hash_type.SSH_PUBLICKEY_HASH_SHA1, out SafePublicKeyHash hash, out nuint hlen);
            using SafePublicKeyHash hashDispose = hash;
            Assert.False(hash.IsInvalid);
            Assert.NotZero(hlen);
            Assert.Zero(errInt);

            ssh_known_hosts_e knownSessionServer = NativeMethods.ssh_session_is_known_server(session);
            Assert.AreEqual(ssh_known_hosts_e.SSH_KNOWN_HOSTS_OK, knownSessionServer);

            ssh_known_hosts_e knownHosts = NativeMethods.ssh_session_has_known_hosts_entry(session);

            Assert.AreEqual(
                ssh_error_e.SSH_OK,
                NativeMethods.ssh_session_export_known_hosts_entry(session, out SafeSshString entryString));
            using SafeSshString entryStringDispose = entryString;

            NativeMethods.ssh_disconnect(session);
            NativeMethods.ssh_silent_disconnect(session);

            err = NativeMethods.ssh_session_update_known_hosts(session);
        }

        [Test]
        [Category("Availability")]
        [Category("System")]
        [Explicit]
        public void SshSession()
        {
            using SafeSshSession session = Connect();

            Assert.True(NativeMethods.ssh_is_blocking(session));
            Assert.True(NativeMethods.ssh_is_connected(session));
        }

        [Test]
        [Category("Availability")]
        [Category("System")]
        [Explicit]
        public void SshChannel()
        {
            using SafeSshSession session = Connect();

            using SafeSshChannel channel = NativeMethods.ssh_channel_new(session);
            Assert.NotNull(channel);
            Assert.False(channel.IsInvalid);

            ssh_error_e err = NativeMethods.ssh_channel_open_session(channel);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            Assert.True(NativeMethods.ssh_channel_is_open(channel));
            Assert.False(NativeMethods.ssh_channel_is_closed(channel));
            Assert.False(NativeMethods.ssh_channel_is_eof(channel));
            Assert.False(NativeMethods.ssh_channel_is_eof(channel));

            NativeMethods.ssh_channel_set_blocking(channel, false);

            byte[] buf = new byte[4096];
            int read = NativeMethods.ssh_channel_read(channel, buf, (uint)buf.Length, false);

            byte[] writeBuf = { (byte)'\b', (byte)'\r', (byte)'\r', (byte)'\r' };
            int written = NativeMethods.ssh_channel_write(channel, writeBuf, (uint)writeBuf.Length);

            err = NativeMethods.ssh_channel_request_exec(channel, "ls");
            Assert.AreNotEqual(ssh_error_e.SSH_ERROR, err);

            int exitStatus = NativeMethods.ssh_channel_get_exit_status(channel);

            int ret = NativeMethods.ssh_channel_send_eof(channel);
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        public void Key()
        {
            using SafeSshKey key = NativeMethods.ssh_key_new();
            Assert.False(key.IsInvalid);
            Assert.NotNull(key);

            Assert.AreEqual(ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, NativeMethods.ssh_key_type(key));
            Assert.AreEqual(ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, NativeMethods.ssh_key_type_from_name(null));

            Assert.True(NativeMethods.ssh_key_cmp(key, key, ssh_keycmp_e.SSH_KEY_CMP_PUBLIC));
            Assert.False(NativeMethods.ssh_key_is_public(key));
            Assert.False(NativeMethods.ssh_key_is_private(key));

            IntPtr keyType = NativeMethods.ssh_key_type_to_char(ssh_keytypes_e.SSH_KEYTYPE_ED25519);
            Assert.AreNotEqual(IntPtr.Zero, keyType);

            string? keyTypeName = Marshal.PtrToStringAnsi(keyType);
            NAssert.NotNull(keyTypeName);
            Assert.AreEqual(ssh_keytypes_e.SSH_KEYTYPE_ED25519, NativeMethods.ssh_key_type_from_name(keyTypeName));

            IntPtr keyTypeUnknown = NativeMethods.ssh_key_type_to_char(ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN);
            Assert.AreEqual(IntPtr.Zero, keyTypeUnknown);
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        public void Buffer()
        {
            using SafeSshBuffer buffer = NativeMethods.ssh_buffer_new();
            byte[] buf = new byte[16];
            int errInt = NativeMethods.ssh_buffer_add_data(buffer, buf, (uint)buf.Length);
            Assert.Zero(errInt);

            IntPtr bufStart = NativeMethods.ssh_buffer_get(buffer);
            Assert.AreNotEqual(IntPtr.Zero, bufStart);

            uint bufLen = NativeMethods.ssh_buffer_get_len(buffer);
            Assert.AreEqual(buf.Length, bufLen);

            bufLen = NativeMethods.ssh_buffer_get_data(buffer, buf, (uint)buf.Length);
            Assert.AreEqual(buf.Length, bufLen);

            errInt = NativeMethods.ssh_buffer_add_data(buffer, buf, (uint)buf.Length);
            Assert.Zero(errInt);

            errInt = NativeMethods.ssh_buffer_reinit(buffer);
            Assert.Zero(errInt);
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        public void SshString()
        {
            nuint size = 16;

            using SafeSshString str = NativeMethods.ssh_string_new(size);
            Assert.AreEqual(size, NativeMethods.ssh_string_len(str));

            using SafeSshString str2 = NativeMethods.ssh_string_copy(str);

            using SafeSshChar chr = NativeMethods.ssh_string_to_char(str);

            NativeMethods.ssh_string_burn(str);

            int errInt = NativeMethods.ssh_string_fill(str, new byte[size], size);
            Assert.Zero(errInt);

            IntPtr data = NativeMethods.ssh_string_get_char(str);
            Assert.AreNotEqual(IntPtr.Zero, data);

            data = NativeMethods.ssh_string_data(str);
            Assert.AreNotEqual(IntPtr.Zero, data);
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        public void Authentication()
        {
            using var session = new SafeSshSession();

            using var key = new SafeSshKey();
            ssh_auth_e errAuth = NativeMethods.ssh_userauth_publickey(session, null, key);
            errAuth = NativeMethods.ssh_userauth_publickey(session, "a", key);
            errAuth = NativeMethods.ssh_userauth_try_publickey(session, null, key);
            errAuth = NativeMethods.ssh_userauth_try_publickey(session, "a", key);
            errAuth = NativeMethods.ssh_userauth_publickey_auto(session, null, null);
            errAuth = NativeMethods.ssh_userauth_publickey_auto(session, "u", "p");

            if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            {
                errAuth = NativeMethods.ssh_userauth_agent(session, null);
                errAuth = NativeMethods.ssh_userauth_agent(session, "a");
            }
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        public void AuthenticationMethod()
        {
            Assert.Pass();
            return;

            using var session = new SafeSshSession();
            ssh_auth_method methods = NativeMethods.ssh_userauth_none(session, null);
            methods = NativeMethods.ssh_userauth_none(session, "a");
            methods = NativeMethods.ssh_userauth_list(session, null);
            methods = NativeMethods.ssh_userauth_list(session, "a");
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        public void PublicPrivateKey()
        {
            ssh_error_e err = NativeMethods.ssh_pki_import_pubkey_file("abc", out SafeSshKey key);
            using var keyDispose = key;
            Assert.AreEqual(ssh_error_e.SSH_EOF, err);

            err = NativeMethods.ssh_pki_import_privkey_file(
                "abc", null, (prompt, buf, len, echo, verify, userdata) => 0, IntPtr.Zero,
                out SafeSshKey keyPrivateFile);
            using var keyPrivateFileDispose = keyPrivateFile;

            err = NativeMethods.ssh_pki_import_privkey_file(
                "abc", "p", (prompt, buf, len, echo, verify, userdata) => 0, IntPtr.Zero,
                out SafeSshKey keyPrivateFilePass);
            using var keyPrivateFilePassDispose = keyPrivateFilePass;

            err = NativeMethods.ssh_pki_import_pubkey_base64(
                new byte[16], ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, out SafeSshKey key64);
            using var key64Dispose = key64;

            err = NativeMethods.ssh_pki_import_privkey_base64(
                new byte[16], null, (prompt, buf, len, echo, verify, userdata) => 0,
                IntPtr.Zero, out SafeSshKey keyPrivate64);
            using var keyPrivate64Dispose = keyPrivate64;

            err = NativeMethods.ssh_pki_copy_cert_to_privkey(key, key);

            err = NativeMethods.ssh_pki_export_privkey_file(
                key, null, (prompt, buf, len, echo, verify, userdata) => 0, IntPtr.Zero, "abc");

            err = NativeMethods.ssh_pki_export_privkey_to_pubkey(key, out SafeSshKey publicKey);
            using var publicKeyDispose = publicKey;
        }

        [Test]
        [Category("Availability")]
        [Explicit]
        public void Free()
        {
            Assert.Pass();
            return;

            NativeMethods.ssh_buffer_free(IntPtr.Zero);
            NativeMethods.ssh_channel_free(IntPtr.Zero);
            NativeMethods.ssh_connector_free(IntPtr.Zero);
            NativeMethods.ssh_event_free(IntPtr.Zero);
            NativeMethods.ssh_free(IntPtr.Zero);
            ssh_knownhosts_entry knownhostsEntry = new ssh_knownhosts_entry();
            NativeMethods.ssh_knownhosts_entry_free(ref knownhostsEntry);
            NativeMethods.ssh_message_free(IntPtr.Zero);
            NativeMethods.ssh_pcap_file_free(IntPtr.Zero);
            NativeMethods.ssh_scp_free(IntPtr.Zero);
            NativeMethods.ssh_key_free(IntPtr.Zero);
            NativeMethods.ssh_string_free(IntPtr.Zero);
            NativeMethods.ssh_buffer_free(IntPtr.Zero);
            NativeMethods.ssh_clean_pubkey_hash(IntPtr.Zero);
        }

        private static SafeSshSession Connect()
        {
            SafeSshSession session = NativeMethods.ssh_new();

            int errInt = NativeMethods.ssh_options_set(session, ssh_options_e.SSH_OPTIONS_HOST, "tty.sdf.org");
            Assert.Zero(errInt);
            errInt = NativeMethods.ssh_options_set(
                session, ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY, ssh_log_e.SSH_LOG_PROTOCOL);
            Assert.Zero(errInt);

            errInt = NativeMethods.ssh_options_set(session, ssh_options_e.SSH_OPTIONS_PORT, 22);
            Assert.Zero(errInt);

            ssh_error_e err = NativeMethods.ssh_connect(session);
            Assert.AreEqual(ssh_error_e.SSH_OK, err);

            ssh_auth_e errAuth = NativeMethods.ssh_userauth_password(session, "myfirstsshserver", "CxS7TDxti5g");
            Assert.AreEqual(ssh_auth_e.SSH_AUTH_SUCCESS, errAuth);
            return session;
        }
    }
}
