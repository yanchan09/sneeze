const std = @import("std");

const c = @cImport({
    @cInclude("quiche.h");
    @cInclude("netinet/in.h");
    @cInclude("uv.h");
});

const log = std.log.scoped(.quic);

const QuicConn = @This();

allocator: std.mem.Allocator,
uv_conn: c.uv_udp_t,
uv_timer: c.uv_timer_t,
uv_send_timer: c.uv_timer_t,
uv_handshake_timeout_timer: c.uv_timer_t,
bound_sockaddr: c.sockaddr_storage,
bound_sockaddr_len: c_int,

quiche_conn: ?*c.quiche_conn = null,
pending_send: ?c.uv_udp_send_t = null,
pending_sendbuf: ?[]u8 = null,
pending_send_sz: usize = 0,
pending_send_dst: ?c.sockaddr_storage = null,
established: bool = false,

cb_ud: *anyopaque,
cb_on_established: ?*const fn (ud: *anyopaque) void = null,

pub fn connect(
    allocator: std.mem.Allocator,
    uv_loop: *c.uv_loop_t,
    peer_addr: std.net.Address,
    peer_name: [:0]const u8,
    callbacks: anytype,
) !*QuicConn {
    var uv_result: c_int = undefined;

    switch (peer_addr.any.family) {
        std.posix.AF.INET => {},
        std.posix.AF.INET6 => {},
        else => return error.UnsupportedAddressType,
    }

    log.debug("enter QuicConn.connect()", .{});

    const conn = try allocator.create(QuicConn);
    errdefer allocator.destroy(conn);

    conn.* = .{
        .allocator = allocator,
        .uv_conn = undefined,
        .uv_timer = undefined,
        .uv_send_timer = undefined,
        .uv_handshake_timeout_timer = undefined,
        .bound_sockaddr = undefined,
        .bound_sockaddr_len = 0,
        .cb_ud = undefined,
    };

    conn.cb_ud = callbacks.object;
    conn.cb_on_established = @ptrCast(callbacks.on_established);

    if (c.uv_udp_init(uv_loop, &conn.uv_conn) < 0) {
        return error.UvError;
    }
    conn.uv_conn.data = conn;

    if (c.uv_timer_init(uv_loop, &conn.uv_timer) < 0) {
        return error.UvError;
    }
    conn.uv_timer.data = conn;

    if (c.uv_timer_init(uv_loop, &conn.uv_send_timer) < 0) {
        return error.UvError;
    }
    conn.uv_send_timer.data = conn;

    if (c.uv_timer_init(uv_loop, &conn.uv_handshake_timeout_timer) < 0) {
        return error.UvError;
    }
    conn.uv_handshake_timeout_timer.data = conn;

    // Bind to all addresses
    if (c.uv_udp_bind(&conn.uv_conn, @ptrCast(&c.sockaddr_in{
        .sin_family = c.AF_INET,
        .sin_port = 0,
        .sin_addr = c.in_addr{
            .s_addr = 0x00000000,
        },
    }), 0) < 0) {
        return error.UvError;
    }

    log.debug("socket bound", .{});

    // Get local sockaddr
    conn.bound_sockaddr_len = @sizeOf(@TypeOf(conn.bound_sockaddr));
    if (c.uv_udp_getsockname(&conn.uv_conn, @ptrCast(&conn.bound_sockaddr), &conn.bound_sockaddr_len) < 0) {
        return error.UvError;
    }

    log.debug("got sockname", .{});

    //      const addrinfo_req = try allocator.create(c.uv_getaddrinfo_t);
    //      errdefer allocator.destroy(addrinfo_req);

    //      addrinfo_req.data = conn;
    //      const addrinfo_hints = c.addrinfo{
    //          .ai_flags = c.AI_ADDRCONFIG,
    //          .ai_socktype = c.SOCK_DGRAM,
    //          .ai_protocol = c.IPPROTO_UDP,
    //      };
    //      if (c.uv_getaddrinfo(uv_loop, addrinfo_req, uv_getaddrinfo_cb, peer_addr.ptr, null, &addrinfo_hints) < 0) {
    //          return error.UvError;
    //      }

    const keylog_path: ?[:0]u8 = blk: {
        const value = std.process.getEnvVarOwned(allocator, "SSLKEYLOGFILE") catch |e| {
            if (e == error.EnvironmentVariableNotFound) break :blk null;
            return e;
        };
        defer allocator.free(value);

        const value_z = try allocator.allocSentinel(u8, value.len, 0);
        @memcpy(value_z, value);
        break :blk value_z;
    };
    defer if (keylog_path) |p| allocator.free(p);

    const quic_cfg = c.quiche_config_new(c.QUICHE_PROTOCOL_VERSION).?;
    const application_protos: []const u8 = "\x11moe.mewmew.sneeze";
    if (c.quiche_config_set_application_protos(quic_cfg, application_protos.ptr, application_protos.len) < 0) {
        c.quiche_config_free(quic_cfg);
        return error.QuicheError;
    }
    c.quiche_config_set_initial_max_streams_bidi(quic_cfg, 1);
    c.quiche_config_set_initial_max_streams_uni(quic_cfg, 16);
    c.quiche_config_set_initial_max_data(quic_cfg, 4096);
    c.quiche_config_set_initial_max_stream_data_bidi_local(quic_cfg, 4096);
    c.quiche_config_set_initial_max_stream_data_bidi_remote(quic_cfg, 4096);
    c.quiche_config_set_initial_max_stream_data_uni(quic_cfg, 4096);
    c.quiche_config_verify_peer(quic_cfg, false);
    c.quiche_config_discover_pmtu(quic_cfg, true);
    if (keylog_path != null) c.quiche_config_log_keys(quic_cfg);
    const scid = std.mem.zeroes([c.QUICHE_MAX_CONN_ID_LEN]u8);

    const peer_sockaddr: *const c.sockaddr = switch (peer_addr.any.family) {
        std.posix.AF.INET => @ptrCast(&peer_addr.in.sa),
        std.posix.AF.INET6 => @ptrCast(&peer_addr.in6.sa),
        else => unreachable,
    };
    const peer_sockaddr_len: usize = switch (peer_addr.any.family) {
        std.posix.AF.INET => @sizeOf(c.sockaddr_in),
        std.posix.AF.INET6 => @sizeOf(c.sockaddr_in6),
        else => unreachable,
    };

    conn.quiche_conn = c.quiche_connect(
        peer_name.ptr,
        scid[0..],
        scid.len,
        @ptrCast(&conn.bound_sockaddr),
        @intCast(conn.bound_sockaddr_len),
        peer_sockaddr,
        @intCast(peer_sockaddr_len),
        quic_cfg,
    );
    log.debug("quiche conn created", .{});
    errdefer c.quiche_conn_free(conn.quiche_conn);

    if (keylog_path) |path| {
        _ = c.quiche_conn_set_keylog_path(conn.quiche_conn, path.ptr);
    }
    c.quiche_config_free(quic_cfg);

    // Start handshake timeout
    uv_result = c.uv_timer_start(&conn.uv_handshake_timeout_timer, uv_handshake_timeout_cb, 10000, 0);
    if (uv_result < 0) {
        log.err("Error creating uv_handshake_timeout_timer: {}", .{uv_result});
        return error.UvError;
    }
    errdefer _ = c.uv_timer_stop(&conn.uv_handshake_timeout_timer);

    if (c.uv_udp_recv_start(&conn.uv_conn, uv_alloc_impl, uv_recv_impl) < 0) {
        return error.UvError;
    }
    errdefer _ = c.uv_udp_recv_stop(&conn.uv_conn);

    // Better to have correct time in quiche_update
    // Note: quiche_connect takes quite a bit of time, ~5 ms.
    c.uv_update_time(uv_loop);
    conn.quiche_update();

    return conn;
}

pub fn uv_handshake_timeout_cb(timer: ?*c.uv_timer_t) callconv(.C) void {
    const this: *QuicConn = @ptrCast(@alignCast(timer.?.data));
    if (!c.quiche_conn_is_closed(this.quiche_conn) and !c.quiche_conn_is_established(this.quiche_conn)) {
        _ = c.quiche_conn_close(this.quiche_conn, false, 0x0c, "", 0);
        this.quiche_update();
    }
}

pub fn send(this: *@This(), data: []const u8) void {
    // might not send everything ...
    _ = c.quiche_conn_stream_send(this.quiche_conn, 0x00, data.ptr, data.len, false, null);
}

pub fn quiche_update(this: *@This()) void {
    log.debug("enter quiche_update", .{});
    this.schedule_sends();
    this.schedule_timers();
    if (!this.established and c.quiche_conn_is_established(this.quiche_conn)) {
        this.established = true;
        _ = c.uv_timer_stop(&this.uv_handshake_timeout_timer);
        log.info("Connection established", .{});
        if (this.cb_on_established) |cb| cb(this.cb_ud);
    }
    if (c.quiche_conn_is_timed_out(this.quiche_conn)) {
        log.info("Connection timed out", .{});
    }
    if (c.quiche_conn_is_draining(this.quiche_conn)) {
        log.info("Connection draining", .{});
    }
    if (c.quiche_conn_is_closed(this.quiche_conn)) {
        _ = c.uv_timer_stop(&this.uv_handshake_timeout_timer);
        log.info("Connection closed", .{});
    }

    var err_is_app: bool = undefined;
    var err_code: u64 = undefined;
    var err_reason: ?[*]const u8 = undefined;
    var err_reason_len: usize = undefined;
    if (c.quiche_conn_peer_error(this.quiche_conn, &err_is_app, &err_code, &err_reason, &err_reason_len)) {
        if (err_reason) |reason_ptr| {
            log.info("Peer error. is_app={}, code={}, reason={s}", .{ err_is_app, err_code, reason_ptr[0..err_reason_len] });
        } else {
            log.info("Peer error. is_app={}, code={}, reason=(null)", .{ err_is_app, err_code });
        }
    }

    if (c.quiche_conn_local_error(this.quiche_conn, &err_is_app, &err_code, &err_reason, &err_reason_len)) {
        if (err_reason) |reason_ptr| {
            log.info("Local error. is_app={}, code={}, reason={s}", .{ err_is_app, err_code, reason_ptr[0..err_reason_len] });
        } else {
            log.info("Local error. is_app={}, code={}, reason=(null)", .{ err_is_app, err_code });
        }
    }
}

pub fn schedule_sends(this: *@This()) void {
    if (this.pending_sendbuf != null) return;

    const quantum = c.quiche_conn_max_send_udp_payload_size(this.quiche_conn);
    const send_buf = std.heap.c_allocator.alloc(u8, quantum) catch unreachable;
    var send_info: c.quiche_send_info = undefined;
    const send_sz = c.quiche_conn_send(this.quiche_conn, send_buf.ptr, send_buf.len, &send_info);
    if (send_sz < -1) {
        log.info("{}", .{send_sz});
        unreachable;
    }
    if (send_sz > 0) {
        const current_time = c.uv_now(this.uv_conn.loop);
        const at_ms: u64 = @as(u64, @intCast(send_info.at.tv_sec)) * 1000 + @divTrunc(@as(u64, @intCast(send_info.at.tv_nsec)) + 500000, 1000000);
        const send_delay = at_ms -| current_time;
        log.info("scheduling send, sendat={}, bytes={}", .{ send_delay, send_sz });

        this.pending_sendbuf = send_buf;
        this.pending_send = undefined;
        this.pending_send_sz = @intCast(send_sz);
        this.pending_send_dst = undefined;
        @memcpy(
            @as([*]u8, @ptrCast(&this.pending_send_dst))[0..send_info.to_len],
            @as([*]const u8, @ptrCast(&send_info.to))[0..send_info.to_len],
        );

        if (send_delay > 0) {
            _ = c.uv_timer_start(&this.uv_send_timer, uv_send_timer_cb, send_delay, 0);
        } else {
            if (c.uv_udp_send(&this.pending_send.?, &this.uv_conn, &c.uv_buf_t{
                .base = send_buf.ptr,
                .len = @intCast(send_sz),
            }, 1, @ptrCast(&send_info.to), uv_send_complete_impl) < 0) {
                unreachable;
            }
        }
    }
}

fn uv_send_timer_cb(handle: ?*c.uv_timer_t) callconv(.C) void {
    log.debug("uv_send_timer_cb", .{});
    const this: *QuicConn = @alignCast(@ptrCast(handle.?.data));
    if (c.uv_udp_send(&this.pending_send.?, &this.uv_conn, &c.uv_buf_t{
        .base = this.pending_sendbuf.?.ptr,
        .len = this.pending_send_sz,
    }, 1, @ptrCast(&this.pending_send_dst.?), uv_send_complete_impl) < 0) {
        unreachable;
    }
}

pub fn schedule_timers(this: *@This()) void {
    const timeout = c.quiche_conn_timeout_as_millis(this.quiche_conn);
    if (timeout != std.math.maxInt(u64)) {
        log.info("{} ms until next timeout", .{timeout});
        _ = c.uv_timer_start(&this.uv_timer, uv_timer_cb, timeout, 0);
    }
}

fn uv_timer_cb(handle: ?*c.uv_timer_t) callconv(.C) void {
    const this: *QuicConn = @alignCast(@ptrCast(handle.?.data));
    c.quiche_conn_on_timeout(this.quiche_conn);
    this.quiche_update();
}

/// Called from the event loop when libuv finishes the pending socket send operation.
fn uv_send_complete_impl(handle: ?*c.uv_udp_send_t, status: c_int) callconv(.C) void {
    const sock_handle: *c.uv_udp_t = handle.?.handle.?;
    const this: *QuicConn = @alignCast(@ptrCast(sock_handle.data));
    if (status < 0) {
        log.err("Failed to send on the QUIC UDP socket: {}", .{status});
        this.pending_send = null;
        this.allocator.free(this.pending_sendbuf.?);
        this.pending_sendbuf = null;
        return;
    }
    log.info("send complete", .{});

    // TODO: we ought to share this logic with quiche_update
    var send_info: c.quiche_send_info = undefined;
    const send_sz = c.quiche_conn_send(this.quiche_conn, this.pending_sendbuf.?.ptr, this.pending_sendbuf.?.len, &send_info);
    if (send_sz < -1) {
        log.info("{}", .{send_sz});
        unreachable;
    } else if (send_sz > 0) {
        log.info("scheduling send", .{});
        if (c.uv_udp_send(&this.pending_send.?, &this.uv_conn, &c.uv_buf_t{
            .base = this.pending_sendbuf.?.ptr,
            .len = @intCast(send_sz),
        }, 1, @ptrCast(&send_info.to), uv_send_complete_impl) < 0) {
            unreachable;
        }
    } else {
        this.pending_send = null;
        this.allocator.free(this.pending_sendbuf.?);
        this.pending_sendbuf = null;
        return;
    }
}

/// Called from the event loop when any data is received on the UDP socket.
fn uv_recv_impl(handle: ?*c.uv_udp_t, nread: isize, buf: ?*const c.uv_buf_t, sockaddr: ?*const c.sockaddr, _: c_uint) callconv(.C) void {
    const this: *QuicConn = @alignCast(@ptrCast(handle.?.data));
    if (nread > 0) {
        const ret = c.quiche_conn_recv(this.quiche_conn, buf.?.base, @intCast(nread), &c.quiche_recv_info{
            .from = @constCast(sockaddr),
            .from_len = @sizeOf(c.sockaddr),
            .to = @ptrCast(&this.bound_sockaddr),
            .to_len = @sizeOf(c.sockaddr),
        });
        if (ret < 0) {
            // TODO: should we do anything more in here?
            log.err("Quiche error handling a received datagram: {}", .{ret});
        }
    }
    if (nread == 0) {
        // nread == 0 signals that no more data is available for reading.
        // Update needs to be triggered as the received packets may warrant a response or a timer update.
        this.quiche_update();
    }
    if (buf.?.base) |ptr| {
        this.allocator.free(ptr[0..buf.?.len]);
    }
}

/// Called when libuv needs to allocate memory for socket receive buffers.
fn uv_alloc_impl(handle: ?*c.uv_handle_t, size: usize, buf: ?*c.uv_buf_t) callconv(.C) void {
    // TODO: should we actually allocate size? iirc it's hardcoded to 64k in libuv
    const this: *QuicConn = @alignCast(@ptrCast(handle.?.data));
    buf.?.base = null;
    buf.?.len = 0;

    // On allocation failure we return to caller with base = null and len = 0.
    // This causes the outer libuv function to signal an allocation error to the application.
    const mem = this.allocator.alloc(u8, size) catch return;
    buf.?.base = mem.ptr;
    buf.?.len = mem.len;
}
