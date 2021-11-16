using System;
using System.Runtime.InteropServices;

using NN.Dnsshe.LibSsh.Native;
using NN.Dnsshe.Native;

using NUnit.Framework;
// ReSharper disable HeuristicUnreachableCode
// ReSharper disable RedundantAssignment
// ReSharper disable UnusedVariable
// ReSharper disable SuggestVarOrType_SimpleTypes
// ReSharper disable SuggestVarOrType_BuiltInTypes
// Using explicit types on purpose
// ReSharper disable NotAccessedVariable

// Use 'var'
#pragma warning disable IDE0007

// The method is obsolete
#pragma warning disable CS0618

// Unreachable code detected
#pragma warning disable CS0162

// Unnecessary assignment of a value
#pragma warning disable IDE0059

namespace NN.Dnsshe.Tests.LibSsh.Native
{
    /// <summary>
    /// The purpose of this test is just to make sure the methods signature is correct.
    /// </summary>
    [Parallelizable(ParallelScope.All)]
    [Category("Availability")]
    public class AvailabilityTests
    {
        [Test]
        [Category("System")]
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
        [Category("System")]
        public void SshSession()
        {
            using SafeSshSession session = Connect();

            Assert.True(NativeMethods.ssh_is_blocking(session));
            Assert.True(NativeMethods.ssh_is_connected(session));
        }

        [Test]
        [Category("System")]
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

            err = NativeMethods.ssh_channel_send_eof(channel);
        }

        [Test]
        public void SshChannelMethods()
        {
            Assert.Pass();
            return;

            using var channel = new SafeSshChannel();

            using SafeSshChannel x11Channel = NativeMethods.ssh_channel_accept_x11(channel, 123);
            ssh_error_e err = NativeMethods.ssh_channel_change_pty_size(channel, 1, 1);

            err = NativeMethods.ssh_channel_close(channel);

            int errInt = NativeMethods.ssh_channel_get_exit_status(channel);

            using SafeSshSession session = NativeMethods.ssh_channel_get_session(channel);

            err = NativeMethods.ssh_channel_open_auth_agent(channel);
            err = NativeMethods.ssh_channel_open_forward(channel, "abc", 1, "abc", 1);
            err = NativeMethods.ssh_channel_open_forward_unix(channel, "abc", "abc", 1);
            err = NativeMethods.ssh_channel_open_x11(channel, "abc", 1);

            errInt = NativeMethods.ssh_channel_poll(channel, true);
            errInt = NativeMethods.ssh_channel_poll_timeout(channel, 1, true);

            errInt = NativeMethods.ssh_channel_read(channel, new byte[1], 1, true);
            errInt = NativeMethods.ssh_channel_read_timeout(channel, new byte[1], 1u, true, 1);
            errInt = NativeMethods.ssh_channel_read_nonblocking(channel, new byte[1], 1u, true);

            err = NativeMethods.ssh_channel_request_env(channel, "a", "b");
            err = NativeMethods.ssh_channel_request_exec(channel, "a");
            err = NativeMethods.ssh_channel_request_pty(channel);
            err = NativeMethods.ssh_channel_request_pty_size(channel, "a", 1, 2);
            err = NativeMethods.ssh_channel_request_shell(channel);
            err = NativeMethods.ssh_channel_request_send_signal(channel, "a");
            err = NativeMethods.ssh_channel_request_send_break(channel, 1);
            err = NativeMethods.ssh_channel_request_sftp(channel);
            err = NativeMethods.ssh_channel_request_subsystem(channel, "a");
            err = NativeMethods.ssh_channel_request_x11(channel, 1, "a", "b", 1);
            err = NativeMethods.ssh_channel_request_auth_agent(channel);
            err = NativeMethods.ssh_channel_send_eof(channel);
            err = NativeMethods.ssh_channel_select(channel, channel, channel, new timeval());
            NativeMethods.ssh_channel_set_blocking(channel, true);
            NativeMethods.ssh_channel_set_counter(channel, new ssh_counter_struct());
            errInt = NativeMethods.ssh_channel_write(channel, new byte[16], 1u);
            errInt = NativeMethods.ssh_channel_write_stderr(channel, new byte[16], 1u);

            uint windowSize = NativeMethods.ssh_channel_window_size(channel);
        }

        [Test]
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

            Assert.Pass();
            return;

            errAuth = NativeMethods.ssh_userauth_password(session, "u", "p");
            errAuth = NativeMethods.ssh_userauth_kbdint(session, "u", null);
            IntPtr instruction = NativeMethods.ssh_userauth_kbdint_getinstruction(session);
            IntPtr name = NativeMethods.ssh_userauth_kbdint_getname(session);
            int nprompts = NativeMethods.ssh_userauth_kbdint_getnprompts(session);
            IntPtr prompts = NativeMethods.ssh_userauth_kbdint_getprompt(session, 0, IntPtr.Zero);
            int answers = NativeMethods.ssh_userauth_kbdint_getnanswers(session);
            IntPtr answer = NativeMethods.ssh_userauth_kbdint_getanswer(session, 0);
            int setAnswer = NativeMethods.ssh_userauth_kbdint_setanswer(session, 0, "a");
            errAuth = NativeMethods.ssh_userauth_gssapi(session);

            if (!OperatingSystem.IsWindows())
            {
                errAuth = NativeMethods.ssh_userauth_agent(session, null);
                errAuth = NativeMethods.ssh_userauth_agent(session, "a");
            }
        }

        [Test]
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
        public void PublicPrivateKey()
        {
            ssh_error_e err = NativeMethods.ssh_pki_generate(ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, 0, out SafeSshKey genKey);
            using var genKeyDispose = genKey;

            // Import
            err = NativeMethods.ssh_pki_import_pubkey_file("abc", out SafeSshKey key);
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

            using var safeSshChar = new SafeSshChar();
            err = NativeMethods.ssh_pki_import_pubkey_base64(
                safeSshChar, ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, out SafeSshKey key64Char);
            using var key64CharDispose = key64Char;

            err = NativeMethods.ssh_pki_import_privkey_base64(
                new byte[16], null, (prompt, buf, len, echo, verify, userdata) => 0,
                IntPtr.Zero, out SafeSshKey keyPrivate64);
            using var keyPrivate64Dispose = keyPrivate64;

            err = NativeMethods.ssh_pki_import_privkey_base64(
                new byte[16], "p", (prompt, buf, len, echo, verify, userdata) => 0,
                IntPtr.Zero, out SafeSshKey keyPrivate64Pass);
            using var keyPrivate64PassDispose = keyPrivate64Pass;

            err = NativeMethods.ssh_pki_import_privkey_base64(
                safeSshChar, null, (prompt, buf, len, echo, verify, userdata) => 0,
                IntPtr.Zero, out SafeSshKey keyPrivate64Char);
            using var keyPrivate64CharDispose = keyPrivate64Char;

            err = NativeMethods.ssh_pki_import_privkey_base64(
                safeSshChar, "p", (prompt, buf, len, echo, verify, userdata) => 0,
                IntPtr.Zero, out SafeSshKey keyPrivate64CharPass);
            using var keyPrivate64CharPassDispose = keyPrivate64CharPass;

            err = NativeMethods.ssh_pki_copy_cert_to_privkey(key, key);

            // Export
            err = NativeMethods.ssh_pki_export_privkey_base64(
                key, null, (prompt, buf, len, echo, verify, userdata) => 0, IntPtr.Zero, out SafeSshChar privateKey64);
            using var privateKey64Dispose = privateKey64;

            err = NativeMethods.ssh_pki_export_privkey_base64(
                key, "p", (prompt, buf, len, echo, verify, userdata) => 0, IntPtr.Zero, out SafeSshChar privateKey64Pass);
            using var privateKey64PassDispose = privateKey64Pass;

            err = NativeMethods.ssh_pki_export_privkey_file(
                key, null, (prompt, buf, len, echo, verify, userdata) => 0, IntPtr.Zero, "abc");

            err = NativeMethods.ssh_pki_export_privkey_file(
                key, "p", (prompt, buf, len, echo, verify, userdata) => 0, IntPtr.Zero, "abc");

            err = NativeMethods.ssh_pki_export_pubkey_file(key, "a");

            err = NativeMethods.ssh_pki_export_pubkey_base64(key, out SafeSshChar keyBase64);
            using var keyBase64Dispose = keyBase64;

            err = NativeMethods.ssh_pki_export_privkey_to_pubkey(key, out SafeSshKey publicKey);
            using var publicKeyDispose = publicKey;

            err = NativeMethods.ssh_pki_import_cert_base64(
                new byte[16], ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, out SafeSshKey keyCert64);
            using var keyCert64Dispose = keyCert64;

            err = NativeMethods.ssh_pki_import_cert_base64(
                safeSshChar, ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN, out SafeSshKey keyCert64Char);
            using var keyCert64CharDispose = keyCert64Char;

            err = NativeMethods.ssh_pki_import_cert_file("a", out SafeSshKey keyCertFile);
            using var keyCertFileDispose = keyCertFile;
        }

        [Test]
        public void Helpers()
        {
            return;

            int pass = NativeMethods.ssh_getpass("abc", new char[16], 16, true, true);
        }


        [Test]
        public void SessionGetters()
        {
            var session = Connect();

            int version = NativeMethods.ssh_get_version(session);
            version = NativeMethods.ssh_get_openssh_version(session);

            IntPtr i = NativeMethods.ssh_get_clientbanner(session);
            i = NativeMethods.ssh_get_serverbanner(session);
            i = NativeMethods.ssh_get_kex_algo(session);
            i = NativeMethods.ssh_get_cipher_out(session);
            i = NativeMethods.ssh_get_hmac_in(session);
            i = NativeMethods.ssh_get_hmac_out(session);
        }

        [Test]
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
