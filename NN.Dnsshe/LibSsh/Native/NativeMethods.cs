using System;
using System.Runtime.InteropServices;
using System.Text;

using JetBrains.Annotations;

using NN.Dnsshe.Native;

// ReSharper disable IdentifierTypo
// ReSharper disable InconsistentNaming

namespace NN.Dnsshe.LibSsh.Native
{
    using ssh_counter = IntPtr;

    using ssh_agent = IntPtr;
    using ssh_buffer = IntPtr;
    using ssh_channel = IntPtr;
    using ssh_message = IntPtr;
    using ssh_pcap_file = IntPtr;
    using ssh_key = IntPtr;
    using ssh_scp = IntPtr;
    using ssh_session = IntPtr;
    using ssh_string = IntPtr;
    using ssh_event = IntPtr;
    using ssh_connector = IntPtr;
    using ssh_gssapi_creds = IntPtr;

    using socket_t = IntPtr;

    /// <summary>
    /// <a href="https://api.libssh.org/stable/structssh__counter__struct.html">ssh_counter_struct</a>
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct ssh_counter_struct
    {
        public ulong in_bytes;

        public ulong out_bytes;

        public ulong in_packets;

        public ulong out_packets;
    }





    /// <summary>
    /// See: <a href="https://api.libssh.org/stable/index.html">libssh API</a>.
    /// </summary>
    [PublicAPI]
    public static class NativeMethods
    {
#if TARGET_WINDOWS
        public const string LibSshNative = "ssh";
#else
        public const string LibSshNative = "libssh";
#endif

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_blocking_flush(SafeSshSession session, int timeout);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_channel_accept_x11(SafeSshChannel channel, int timeout_ms);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_change_pty_size(SafeSshChannel channel, int cols, int rows);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_close(ssh_channel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_channel_free(ssh_channel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_get_exit_status(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern SafeSshSession ssh_channel_get_session(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_is_closed(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_is_eof(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_is_open(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern SafeSshChannel ssh_channel_new(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_open_auth_agent(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_open_forward(SafeSshChannel channel, string remotehost, int remoteport, string sourcehost, int localport);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_open_forward_unix(SafeSshChannel channel, string remotepath, string sourcehost, int localport);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_open_session(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_open_x11(SafeSshChannel channel, string orig_addr, int orig_port);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_poll(SafeSshChannel channel, bool is_stderr);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_poll_timeout(SafeSshChannel channel, int timeout, bool is_stderr);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_read(SafeSshChannel channel, byte[] dest, uint count, bool is_stderr);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_read_timeout(SafeSshChannel channel, byte[] dest, uint count, bool is_stderr, int timeout_ms);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_read_nonblocking(SafeSshChannel channel, byte[] dest, uint count, bool is_stderr);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_env(SafeSshChannel channel, string name, string value);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_exec(SafeSshChannel channel, string cmd);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_pty(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_pty_size(SafeSshChannel channel, string term, int cols, int rows);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_shell(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_send_signal(SafeSshChannel channel, string signum);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_send_break(SafeSshChannel channel, uint length);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_sftp(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_subsystem(SafeSshChannel channel, string subsystem);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_x11(SafeSshChannel channel, int single_connection, string protocol, string cookie, int screen_number);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_channel_request_auth_agent(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_send_eof(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_select(ref IntPtr readchans, ref IntPtr writechans, ref IntPtr exceptchans, ref timeval timeout);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_channel_set_blocking(SafeSshChannel channel, int blocking);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_channel_set_counter(SafeSshChannel channel, ref ssh_counter_struct counter);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_write(SafeSshChannel channel, byte[] data, uint len);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_write_stderr(SafeSshChannel channel, byte[] data, uint len);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern uint ssh_channel_window_size(SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_basename(string path);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_clean_pubkey_hash(in IntPtr hash);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_connect(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_connector_new(SafeSshSession session);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_connector_free(IntPtr connector);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_connector_set_in_channel(IntPtr connector, SafeSshChannel channel, ssh_connector_flags_e flags);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_connector_set_out_channel(IntPtr connector, SafeSshChannel channel, ssh_connector_flags_e flags);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_connector_set_in_fd(IntPtr connector, socket_t fd);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_connector_set_out_fd(IntPtr connector, socket_t fd);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_copyright();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_disconnect(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_dirname(string path);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_finalize();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_channel_accept_forward(SafeSshSession session, int timeout_ms, ref int destination_port);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_cancel_forward(SafeSshSession session, string address, int port);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_channel_listen_forward(SafeSshSession session, string address, int port, ref int bound_port);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_free(ssh_session session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_disconnect_message(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern string ssh_get_error(IntPtr error);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_get_error_code(IntPtr error);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern socket_t ssh_get_fd(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_hexa(string what, nuint len);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_issue_banner(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_get_openssh_version(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_error_e ssh_get_server_publickey(SafeSshSession session, out SafeSshKey key);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_get_publickey_hash(SafeSshKey key, ssh_publickey_hash_type type, out SafePublicKeyHash hash, out nuint hlen);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        [Obsolete("Use " + nameof(ssh_get_publickey_hash))]
        public static extern int ssh_get_pubkey_hash(SafeSshSession session, ref IntPtr hash);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_forward_accept(SafeSshSession session, int timeout_ms);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_forward_cancel(SafeSshSession session, string address, int port);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_forward_listen(SafeSshSession session, string address, int port, ref int bound_port);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        [Obsolete("Use " + nameof(ssh_get_server_publickey))]
        public static extern int ssh_get_publickey(SafeSshSession session, ref SafeSshKey key);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        [Obsolete("Use " + nameof(ssh_session_update_known_hosts))]
        public static extern int ssh_write_knownhost(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        [Obsolete("Use " + nameof(ssh_session_export_known_hosts_entry))]   
        public static extern IntPtr ssh_dump_knownhost(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        [Obsolete("Use " + nameof(ssh_session_is_known_server))]
        public static extern int ssh_is_server_known(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_print_hexa(string descr, string what, nuint len);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_get_random(IntPtr where, int len, int strong);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_get_version(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_get_status(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_get_poll_flags(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_init();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_is_blocking(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_is_connected(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_knownhosts_entry_free(ref ssh_knownhosts_entry entry);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_known_hosts_parse_line(string host, string line, ref IntPtr entry);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_known_hosts_e ssh_session_has_known_hosts_entry(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_session_export_known_hosts_entry(SafeSshSession session, ref IntPtr pentry_string);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_session_update_known_hosts(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_known_hosts_e ssh_session_get_known_hosts_entry(SafeSshSession session, ref IntPtr pentry);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_known_hosts_e ssh_session_is_known_server(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_set_log_level(int level);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_get_log_level();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_log_userdata();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_set_log_userdata(byte[] data);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_message_channel_request_open_reply_accept(IntPtr msg);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_message_channel_request_open_reply_accept_channel(IntPtr msg, IntPtr chan);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_message_channel_request_reply_success(IntPtr msg);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_message_free(IntPtr msg);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_message_get(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_message_subtype(IntPtr msg);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_message_type(IntPtr msg);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_mkdir(string pathname, int mode);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern SafeSshSession ssh_new();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_options_copy(IntPtr src, ref IntPtr dest);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_options_parse_config(SafeSshSession session, string filename);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_options_set(SafeSshSession session, ssh_options_e type, nint value);

        // Overloads
        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_options_set(SafeSshSession session, ssh_options_e type, string value);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_options_set(SafeSshSession session, ssh_options_e type, in ssh_log_e value);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_options_set(SafeSshSession session, ssh_options_e type, in int value);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_options_get(SafeSshSession session, ssh_options_e type, ref nint value);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_options_get_port(SafeSshSession session, out uint port_target);
    
        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pcap_file_close(IntPtr pcap);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_pcap_file_free(IntPtr pcap);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_pcap_file_new();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pcap_file_open(IntPtr pcap, string filename);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern SafeSshKey ssh_key_new();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_key_free(ssh_key key);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_keytypes_e ssh_key_type(SafeSshKey key);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_key_type_to_char(ssh_keytypes_e type);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_keytypes_e ssh_key_type_from_name(string? name);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool ssh_key_is_public(SafeSshKey k);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool ssh_key_is_private(SafeSshKey k);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern bool ssh_key_cmp(SafeSshKey k1, SafeSshKey k2, ssh_keycmp_e what);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_generate(ssh_keytypes_e type, int parameter, ref IntPtr pkey);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_import_privkey_base64(string b64_key, string passphrase, ssh_auth_callback auth_fn, IntPtr auth_data, ref IntPtr pkey);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_export_privkey_base64(IntPtr privkey, string passphrase, ssh_auth_callback auth_fn, IntPtr auth_data, ref IntPtr b64_key);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_import_privkey_file(string filename, string passphrase, ssh_auth_callback auth_fn, IntPtr auth_data, ref IntPtr pkey);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_export_privkey_file(IntPtr privkey, string passphrase, ssh_auth_callback auth_fn, IntPtr auth_data, string filename);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_copy_cert_to_privkey(IntPtr cert_key, IntPtr privkey);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_import_pubkey_base64(string b64_key, ssh_keytypes_e type, ref IntPtr pkey);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_import_pubkey_file(string filename, ref IntPtr pkey);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_import_cert_base64(string b64_cert, ssh_keytypes_e type, ref IntPtr pkey);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_import_cert_file(string filename, ref IntPtr pkey);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_export_privkey_to_pubkey(IntPtr privkey, ref IntPtr pkey);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_export_pubkey_base64(SafeSshKey key, ref IntPtr b64_key);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_pki_export_pubkey_file(SafeSshKey key, string filename);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_pki_key_ecdsa_name(SafeSshKey key);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_fingerprint_hash(ssh_publickey_hash_type type, IntPtr hash, nuint len);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_print_hash(ssh_publickey_hash_type type, IntPtr hash, nuint len);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_send_ignore(SafeSshSession session, string data);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_send_debug(SafeSshSession session, string message, int always_display);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_gssapi_set_creds(SafeSshSession session, IntPtr creds);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_accept_request(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_close(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_deny_request(IntPtr scp, string reason);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_scp_free(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_init(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_leave_directory(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_scp_new(SafeSshSession session, int mode, string location);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_pull_request(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_push_directory(IntPtr scp, string dirname, int mode);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_push_file(IntPtr scp, string filename, nuint size, int perms);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_push_file64(IntPtr scp, string filename, ulong size, int perms);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_read(IntPtr scp, IntPtr buffer, nuint size);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_scp_request_get_filename(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_request_get_permissions(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern nuint ssh_scp_request_get_size(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ulong ssh_scp_request_get_size64(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_scp_request_get_warning(IntPtr scp);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_scp_write(IntPtr scp, IntPtr buffer, nuint len);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_select(ref SafeSshChannel channels, ref IntPtr outchannels, socket_t maxfd, ref fd_set readfds, ref timeval timeout);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_service_request(SafeSshSession session, string service);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_set_agent_channel(SafeSshSession session, SafeSshChannel channel);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_set_agent_socket(SafeSshSession session, socket_t fd);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_set_blocking(SafeSshSession session, int blocking);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_set_counters(SafeSshSession session, ref ssh_counter_struct scounter, ref ssh_counter_struct rcounter);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_set_fd_except(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_set_fd_toread(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_set_fd_towrite(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_silent_disconnect(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_set_pcap_file(SafeSshSession session, IntPtr pcapfile);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_auth_e ssh_userauth_none(SafeSshSession session, string username);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_auth_e ssh_userauth_list(SafeSshSession session, string username);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_auth_e ssh_userauth_try_publickey(SafeSshSession session, string username, IntPtr pubkey);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_auth_e ssh_userauth_publickey(SafeSshSession session, string username, IntPtr privkey);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_auth_e ssh_userauth_publickey_auto(SafeSshSession session, string username, string passphrase);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern ssh_auth_e ssh_userauth_password(SafeSshSession session, string username, string password);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_userauth_kbdint(SafeSshSession session, string user, string submethods);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_userauth_kbdint_getinstruction(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_userauth_kbdint_getname(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_userauth_kbdint_getnprompts(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_userauth_kbdint_getprompt(SafeSshSession session, uint i, IntPtr echo);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_userauth_kbdint_getnanswers(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_userauth_kbdint_getanswer(SafeSshSession session, uint i);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_userauth_kbdint_setanswer(SafeSshSession session, uint i, string answer);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_userauth_gssapi(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_version(int req_version);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_string_burn(IntPtr str);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_string_copy(IntPtr str);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_string_data(IntPtr str);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_string_fill(IntPtr str, byte[] data, nuint len);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_string_free(IntPtr str);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_string_from_char(string what);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern nint ssh_string_len(IntPtr str);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_string_new(nuint size);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_string_get_char(IntPtr str);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_string_to_char(IntPtr str);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_string_free_char(IntPtr s);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_getpass(string prompt, IntPtr buf, nuint len, int echo, int verify);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_event_new();




        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_event_add_fd(IntPtr @event, socket_t fd, short events, ssh_event_callback cb, IntPtr userdata);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_event_add_session(IntPtr @event, SafeSshSession session);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_event_add_connector(IntPtr @event, IntPtr connector);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_event_dopoll(IntPtr @event, int timeout);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_event_remove_fd(IntPtr @event, socket_t fd);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_event_remove_session(IntPtr @event, SafeSshSession session);



        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_event_remove_connector(IntPtr @event, IntPtr connector);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_event_free(IntPtr @event);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_clientbanner(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_serverbanner(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_kex_algo(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_cipher_in(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_cipher_out(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_hmac_in(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_get_hmac_out(SafeSshSession session);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_buffer_new();

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern void ssh_buffer_free(IntPtr buffer);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_buffer_reinit(IntPtr buffer);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int ssh_buffer_add_data(IntPtr buffer, byte[] data, uint len);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern uint ssh_buffer_get_data(IntPtr buffer, byte[] data, uint requestedlen);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern IntPtr ssh_buffer_get(IntPtr buffer);

        [DllImport(LibSshNative, ExactSpelling = true, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern uint ssh_buffer_get_len(IntPtr buffer);
    }

    [PublicAPI]
    public enum ssh_error_e
    {
        /// <summary>
        /// No error
        /// </summary>
        SSH_OK = 0,
        /// <summary>
        /// Error of some kind
        /// </summary>
        SSH_ERROR = -1,
        /// <summary>
        /// The nonblocking call must be repeated
        /// </summary>
        SSH_AGAIN = -2,
        /// <summary>
        /// We have already a eof
        /// </summary>
        SSH_EOF = -127
    }

    [PublicAPI]
    public enum ssh_log_e
    {
        SSH_LOG_NOLOG = 0,

        SSH_LOG_WARNING,

        SSH_LOG_PROTOCOL,

        SSH_LOG_PACKET,

        SSH_LOG_FUNCTIONS,
    }

    [PublicAPI]
    public enum ssh_options_e
    {
        SSH_OPTIONS_HOST,

        SSH_OPTIONS_PORT,

        SSH_OPTIONS_PORT_STR,

        SSH_OPTIONS_FD,

        SSH_OPTIONS_USER,

        SSH_OPTIONS_SSH_DIR,

        SSH_OPTIONS_IDENTITY,

        SSH_OPTIONS_ADD_IDENTITY,

        SSH_OPTIONS_KNOWNHOSTS,

        SSH_OPTIONS_TIMEOUT,

        SSH_OPTIONS_TIMEOUT_USEC,

        SSH_OPTIONS_SSH1,

        SSH_OPTIONS_SSH2,

        SSH_OPTIONS_LOG_VERBOSITY,

        SSH_OPTIONS_LOG_VERBOSITY_STR,

        SSH_OPTIONS_CIPHERS_C_S,

        SSH_OPTIONS_CIPHERS_S_C,

        SSH_OPTIONS_COMPRESSION_C_S,

        SSH_OPTIONS_COMPRESSION_S_C,

        SSH_OPTIONS_PROXYCOMMAND,

        SSH_OPTIONS_BINDADDR,

        SSH_OPTIONS_STRICTHOSTKEYCHECK,

        SSH_OPTIONS_COMPRESSION,

        SSH_OPTIONS_COMPRESSION_LEVEL,

        SSH_OPTIONS_KEY_EXCHANGE,

        SSH_OPTIONS_HOSTKEYS,

        SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,

        SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,

        SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,

        SSH_OPTIONS_HMAC_C_S,

        SSH_OPTIONS_HMAC_S_C,

        SSH_OPTIONS_PASSWORD_AUTH,

        SSH_OPTIONS_PUBKEY_AUTH,

        SSH_OPTIONS_KBDINT_AUTH,

        SSH_OPTIONS_GSSAPI_AUTH,

        SSH_OPTIONS_GLOBAL_KNOWNHOSTS,

        SSH_OPTIONS_NODELAY,

        SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES,

        SSH_OPTIONS_PROCESS_CONFIG,

        SSH_OPTIONS_REKEY_DATA,

        SSH_OPTIONS_REKEY_TIME,
    }

    public enum ssh_kex_types_e
    {
        SSH_KEX = 0,

        SSH_HOSTKEYS,

        SSH_CRYPT_C_S,

        SSH_CRYPT_S_C,

        SSH_MAC_C_S,

        SSH_MAC_S_C,

        SSH_COMP_C_S,

        SSH_COMP_S_C,

        SSH_LANG_C_S,

        SSH_LANG_S_C,
    }

    public enum ssh_auth_e
    {
        SSH_AUTH_SUCCESS = 0,

        SSH_AUTH_DENIED,

        SSH_AUTH_PARTIAL,

        SSH_AUTH_INFO,

        SSH_AUTH_AGAIN,

        SSH_AUTH_ERROR = -1,
    }

    public enum ssh_requests_e
    {
        SSH_REQUEST_AUTH = 1,

        SSH_REQUEST_CHANNEL_OPEN,

        SSH_REQUEST_CHANNEL,

        SSH_REQUEST_SERVICE,

        SSH_REQUEST_GLOBAL,
    }

    public enum ssh_channel_type_e
    {
        SSH_CHANNEL_UNKNOWN = 0,

        SSH_CHANNEL_SESSION,

        SSH_CHANNEL_DIRECT_TCPIP,

        SSH_CHANNEL_FORWARDED_TCPIP,

        SSH_CHANNEL_X11,

        SSH_CHANNEL_AUTH_AGENT,
    }

    public enum ssh_channel_requests_e
    {
        SSH_CHANNEL_REQUEST_UNKNOWN = 0,

        SSH_CHANNEL_REQUEST_PTY,

        SSH_CHANNEL_REQUEST_EXEC,

        SSH_CHANNEL_REQUEST_SHELL,

        SSH_CHANNEL_REQUEST_ENV,

        SSH_CHANNEL_REQUEST_SUBSYSTEM,

        SSH_CHANNEL_REQUEST_WINDOW_CHANGE,

        SSH_CHANNEL_REQUEST_X11,
    }

    public enum ssh_global_requests_e
    {
        SSH_GLOBAL_REQUEST_UNKNOWN = 0,

        SSH_GLOBAL_REQUEST_TCPIP_FORWARD,

        SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD,

        SSH_GLOBAL_REQUEST_KEEPALIVE,
    }

    public enum ssh_publickey_state_e
    {
        SSH_PUBLICKEY_STATE_ERROR = -1,

        SSH_PUBLICKEY_STATE_NONE = 0,

        SSH_PUBLICKEY_STATE_VALID = 1,

        SSH_PUBLICKEY_STATE_WRONG = 2,
    }

    public enum ssh_server_known_e
    {
        SSH_SERVER_ERROR = -1,

        SSH_SERVER_NOT_KNOWN = 0,

        SSH_SERVER_KNOWN_OK,

        SSH_SERVER_KNOWN_CHANGED,

        SSH_SERVER_FOUND_OTHER,

        SSH_SERVER_FILE_NOT_FOUND,
    }

    public enum ssh_known_hosts_e
    {
        SSH_KNOWN_HOSTS_ERROR = -2,

        SSH_KNOWN_HOSTS_NOT_FOUND = -1,

        SSH_KNOWN_HOSTS_UNKNOWN = 0,

        SSH_KNOWN_HOSTS_OK,

        SSH_KNOWN_HOSTS_CHANGED,

        SSH_KNOWN_HOSTS_OTHER,
    }

    public enum ssh_error_types_e
    {
        SSH_NO_ERROR = 0,

        SSH_REQUEST_DENIED,

        SSH_FATAL,

        SSH_EINTR,
    }

    public enum ssh_keytypes_e
    {
        SSH_KEYTYPE_UNKNOWN = 0,

        SSH_KEYTYPE_DSS = 1,

        SSH_KEYTYPE_RSA,

        SSH_KEYTYPE_RSA1,

        SSH_KEYTYPE_ECDSA,

        SSH_KEYTYPE_ED25519,

        SSH_KEYTYPE_DSS_CERT01,

        SSH_KEYTYPE_RSA_CERT01,

        SSH_KEYTYPE_ECDSA_P256,

        SSH_KEYTYPE_ECDSA_P384,

        SSH_KEYTYPE_ECDSA_P521,

        SSH_KEYTYPE_ECDSA_P256_CERT01,

        SSH_KEYTYPE_ECDSA_P384_CERT01,

        SSH_KEYTYPE_ECDSA_P521_CERT01,

        SSH_KEYTYPE_ED25519_CERT01,
    }

    public enum ssh_keycmp_e
    {
        SSH_KEY_CMP_PUBLIC = 0,

        SSH_KEY_CMP_PRIVATE,
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ssh_knownhosts_entry
    {
        /// char*
        [MarshalAs(UnmanagedType.LPStr)]
        public string hostname;

        /// char*
        [MarshalAs(UnmanagedType.LPStr)]
        public string unparsed;

        /// ssh_key->ssh_key_struct*
        public System.IntPtr publickey;

        /// char*
        [MarshalAs(UnmanagedType.LPStr)]
        public string comment;
    }



    public enum ssh_mode_e
    {
        SSH_SCP_WRITE,

        SSH_SCP_READ,

        SSH_SCP_RECURSIVE = 16,
    }

    public enum ssh_scp_request_types
    {
        SSH_SCP_REQUEST_NEWDIR = 1,

        SSH_SCP_REQUEST_NEWFILE,

        SSH_SCP_REQUEST_EOF,

        SSH_SCP_REQUEST_ENDDIR,

        SSH_SCP_REQUEST_WARNING,
    }

    public enum ssh_connector_flags_e
    {
        SSH_CONNECTOR_STDOUT = 1,

        SSH_CONNECTOR_STDINOUT = 1,

        SSH_CONNECTOR_STDERR = 2,

        SSH_CONNECTOR_BOTH = 3,
    }

    public enum ssh_publickey_hash_type
    {
        SSH_PUBLICKEY_HASH_SHA1,

        SSH_PUBLICKEY_HASH_MD5,

        SSH_PUBLICKEY_HASH_SHA256,
    }

    public delegate int ssh_auth_callback(string prompt, System.IntPtr buf, System.IntPtr len, int echo, int verify, System.IntPtr userdata);

    public delegate int ssh_event_callback(System.IntPtr fd, int revents, System.IntPtr userdata);
}
