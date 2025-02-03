const std = @import("std");
const uv = @import("./bindings/uv.zig");
const pa = @import("./bindings/pa.zig");
const pw = @import("./bindings/pw.zig");
const pod = @import("./bindings/spa_pod.zig");
const dbus = @import("./bindings/dbus.zig");

const c = @cImport({
    @cInclude("opus/opus.h");
    @cInclude("quiche.h");
    @cInclude("netinet/in.h");
    @cInclude("uv.h");
});

var g_input_m = std.Thread.Mutex{};
var g_input_c = std.Thread.Condition{};
var g_input_ringbuf: std.RingBuffer = undefined;
var g_output_m = std.Thread.Mutex{};
var g_output_ringbuf: std.RingBuffer = undefined;
var g_opus_encoder: *c.OpusEncoder = undefined;
var g_output_notif: c.uv_async_t = undefined;

pub fn input_encoder(ally: std.mem.Allocator) void {
    const encode_input_buf = ally.allocWithOptions(u8, 7680, @sizeOf(f32), null) catch unreachable;
    const encoded_frame = ally.alloc(u8, 1276) catch unreachable;

    g_input_m.lock();
    defer g_input_m.unlock();

    while (true) {
        while (g_input_ringbuf.len() < encode_input_buf.len) g_input_c.wait(&g_input_m);

        g_input_ringbuf.readFirstAssumeLength(encode_input_buf, encode_input_buf.len);

        {
            // UNLOCKED BLOCK
            g_input_m.unlock();
            defer g_input_m.lock();

            const payload_sz_or_err = c.opus_encode_float(g_opus_encoder, @ptrCast(encode_input_buf.ptr), @intCast(encode_input_buf.len / 8), encoded_frame.ptr, 1276);
            if (payload_sz_or_err < 0) unreachable;

            g_output_m.lock();
            g_output_ringbuf.writeSlice(encoded_frame[0..@intCast(payload_sz_or_err)]) catch {
                std.log.warn("output buffer overflow. lost {} bytes", .{payload_sz_or_err});
            };
            g_output_m.unlock();
            _ = c.uv_async_send(&g_output_notif);
            //std.log.info("encoder: output {} bytes", .{payload_sz_or_err});
        }
    }
}

const MicrophoneStreamEvents = struct {
    id: []const u8,
    stream: ?pw.Stream = null,

    pub fn param_changed(self: *@This(), id: u32, _: [*]const u8) void {
        std.log.info("{s}: param_changed({})", .{ self.id, id });
    }

    pub fn process(self: *@This()) void {
        const buffer = self.stream.?.dequeue_buffer() catch unreachable;
        //std.log.info("{s}: process. time={}. bufsize={}", .{ self.id, buffer.time, buffer.buffer.datas[0].chunk.size });

        const raw_buf = buffer.buffer.datas[0].data.?[0..buffer.buffer.datas[0].chunk.size];

        g_input_m.lock();
        blk: {
            g_input_ringbuf.writeSlice(raw_buf) catch {
                std.log.warn("input buffer overflow. lost {} bytes", .{raw_buf.len});
                g_input_m.unlock();
                break :blk;
            };
            g_input_m.unlock();
            g_input_c.signal();
        }

        self.stream.?.queue_buffer(buffer) catch unreachable;
    }
};

const SpaParam = struct {
    pub const Invalid: u32 = 0;
    pub const PropInfo: u32 = 1;
    pub const Props: u32 = 2;
    pub const EnumFormat: u32 = 3;
    pub const Format: u32 = 4;
    pub const Buffers: u32 = 5;
    pub const Meta: u32 = 6;
    pub const IO: u32 = 7;
    pub const EnumProfile: u32 = 8;
    pub const Profile: u32 = 9;
    pub const EnumPortConfig: u32 = 10;
    pub const PortConfig: u32 = 11;
    pub const EnumRoute: u32 = 12;
    pub const Route: u32 = 13;
    pub const Control: u32 = 14;
    pub const Latency: u32 = 15;
    pub const ProcessLatency: u32 = 16;
    pub const Tag: u32 = 17;
};

const SpaFormatProps = struct {
    pub const MediaType: u32 = 1;
    pub const MediaSubtype: u32 = 2;
    pub const AudioFormat: u32 = 65537;
    pub const AudioRate: u32 = 65539;
    pub const AudioChannels: u32 = 65540;
    pub const VideoFormat: u32 = 131073;
    pub const VideoSize: u32 = 131075;
    pub const VideoFramerate: u32 = 131076;
};

const SpaParamBuffersProps = struct {
    pub const Size: u32 = 3;
};

const SpaMediaType = struct {
    pub const Unknown: u32 = 0;
    pub const Audio: u32 = 1;
    pub const Video: u32 = 2;
    pub const Image: u32 = 3;
    pub const Binary: u32 = 4;
    pub const Stream: u32 = 5;
    pub const Application: u32 = 6;
};

const SpaMediaSubtype = struct {
    pub const Unknown: u32 = 0;
    pub const Raw: u32 = 1;
};

pub fn QuicCallbacks(T: type) type {
    return struct {
        object: *T,
        on_established: ?*const fn (ud: *T) void,
    };
}

pub const QuicConn = struct {
    allocator: std.mem.Allocator,
    uv_conn: c.uv_udp_t,
    uv_timer: c.uv_timer_t,
    uv_send_timer: c.uv_timer_t,
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
        switch (peer_addr.any.family) {
            std.posix.AF.INET => {},
            std.posix.AF.INET6 => {},
            else => return error.UnsupportedAddressType,
        }

        const conn = try allocator.create(QuicConn);
        errdefer allocator.destroy(conn);

        conn.* = .{
            .allocator = allocator,
            .uv_conn = undefined,
            .uv_timer = undefined,
            .uv_send_timer = undefined,
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

        // Get local sockaddr
        conn.bound_sockaddr_len = @sizeOf(@TypeOf(conn.bound_sockaddr));
        if (c.uv_udp_getsockname(&conn.uv_conn, @ptrCast(&conn.bound_sockaddr), &conn.bound_sockaddr_len) < 0) {
            return error.UvError;
        }

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
        const application_protos: []const u8 = "\x02ag";
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
        if (keylog_path) |path| {
            _ = c.quiche_conn_set_keylog_path(conn.quiche_conn, path.ptr);
        }
        c.quiche_config_free(quic_cfg);

        conn.quiche_update();

        if (c.uv_udp_recv_start(&conn.uv_conn, uv_alloc_impl, uv_recv_impl) < 0) {
            return error.UvError;
        }
        return conn;
    }

    pub fn send(this: *@This(), data: []const u8) void {
        // might not send everything ...
        _ = c.quiche_conn_stream_send(this.quiche_conn, 0x00, data.ptr, data.len, false, null);
    }

    pub fn quiche_update(this: *@This()) void {
        this.schedule_sends();
        this.schedule_timers();
        if (!this.established and c.quiche_conn_is_established(this.quiche_conn)) {
            this.established = true;
            std.log.info("quic: Connection established", .{});
            if (this.cb_on_established) |cb| cb(this.cb_ud);
        }
    }

    pub fn schedule_sends(this: *@This()) void {
        if (this.pending_sendbuf != null) return;

        const quantum = c.quiche_conn_max_send_udp_payload_size(this.quiche_conn);
        const send_buf = std.heap.c_allocator.alloc(u8, quantum) catch unreachable;
        var send_info: c.quiche_send_info = undefined;
        const send_sz = c.quiche_conn_send(this.quiche_conn, send_buf.ptr, send_buf.len, &send_info);
        if (send_sz < -1) {
            std.log.info("quiche: {}", .{send_sz});
            unreachable;
        }
        if (send_sz > 0) {
            const current_time = c.uv_now(this.uv_conn.loop);
            const at_ms: u64 = @as(u64, @intCast(send_info.at.tv_sec)) * 1000 + @divTrunc(@as(u64, @intCast(send_info.at.tv_nsec)) + 500000, 1000000);
            const send_delay = at_ms -| current_time;
            std.log.info("quiche: scheduling send, sendat={}, bytes={}", .{ send_delay, send_sz });

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
        if (timeout > 0) {
            std.log.info("quiche: {} ms until next timeout", .{timeout});
            _ = c.uv_timer_start(&this.uv_timer, uv_timer_cb, timeout, 0);
        }
    }

    fn uv_timer_cb(handle: ?*c.uv_timer_t) callconv(.C) void {
        const this: *QuicConn = @alignCast(@ptrCast(handle.?.data));
        std.log.info("quiche: timeout", .{});
        c.quiche_conn_on_timeout(this.quiche_conn);
        this.quiche_update();
    }

    //    fn uv_getaddrinfo_cb(handle: ?*c.uv_getaddrinfo_t, status: c_int, res: ?*c.addrinfo) callconv(.C) void {
    //        const this: *QuicConn = @alignCast(@ptrCast(handle.?.data));
    //        // Make sure we free the temporary uv_getaddrinfo_t
    //        defer this.allocator.destroy(handle.?);
    //
    //        defer c.uv_freeaddrinfo(res);
    //
    //        if (status < 0) {
    //            std.log.err("Failed to look up the address: {s}", .{
    //                @as([*:0]const u8, c.uv_strerror(status)),
    //            });
    //            return;
    //        } else {
    //            var iter_entry = res;
    //            while (iter_entry != null) {
    //                if (iter_entry.?.ai_family == c.AF_INET) {
    //                    var ia: c.sockaddr_in = undefined;
    //                    const ia_sz = @sizeOf(@TypeOf(ia));
    //                    if (iter_entry.?.ai_addrlen != ia_sz) unreachable;
    //                    @memcpy(
    //                        @as([*]u8, @ptrCast(&ia))[0..ia_sz],
    //                        @as([*]const u8, @ptrCast(iter_entry.?.ai_addr))[0..ia_sz],
    //                    );
    //
    //                    const z_addr = std.net.Address.initPosix(@ptrCast(&ia));
    //                    std.log.info("- IPv4: {?}, flags={}, socktype={}, protocol={}", .{
    //                        z_addr,
    //                        iter_entry.?.ai_flags,
    //                        iter_entry.?.ai_socktype,
    //                        iter_entry.?.ai_protocol,
    //                    });
    //                } else if (iter_entry.?.ai_family == c.AF_INET6) {
    //                    var ia: c.sockaddr_in6 = undefined;
    //                    const ia_sz = @sizeOf(@TypeOf(ia));
    //                    if (iter_entry.?.ai_addrlen != ia_sz) unreachable;
    //                    @memcpy(
    //                        @as([*]u8, @ptrCast(&ia))[0..ia_sz],
    //                        @as([*]const u8, @ptrCast(iter_entry.?.ai_addr))[0..ia_sz],
    //                    );
    //
    //                    const z_addr = std.net.Address.initPosix(@ptrCast(&ia));
    //                    std.log.info("- IPv6: {?}, flags={}, socktype={}, protocol={}", .{
    //                        z_addr,
    //                        iter_entry.?.ai_flags,
    //                        iter_entry.?.ai_socktype,
    //                        iter_entry.?.ai_protocol,
    //                    });
    //                }
    //                iter_entry = iter_entry.?.ai_next;
    //            }
    //        }
    //    }

    fn uv_send_complete_impl(handle: ?*c.uv_udp_send_t, status: c_int) callconv(.C) void {
        const sock_handle: *c.uv_udp_t = handle.?.handle.?;
        const this: *QuicConn = @alignCast(@ptrCast(sock_handle.data));
        if (status < 0) {
            std.log.err("Failed to send on the QUIC UDP socket: {}", .{status});
            this.pending_send = null;
            this.allocator.free(this.pending_sendbuf.?);
            this.pending_sendbuf = null;
            return;
        }
        std.log.info("quiche: send complete", .{});

        var send_info: c.quiche_send_info = undefined;
        const send_sz = c.quiche_conn_send(this.quiche_conn, this.pending_sendbuf.?.ptr, this.pending_sendbuf.?.len, &send_info);
        if (send_sz < -1) {
            std.log.info("quiche: {}", .{send_sz});
            unreachable;
        } else if (send_sz > 0) {
            std.log.info("quiche: scheduling send", .{});
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

    pub fn uv_recv_impl(handle: ?*c.uv_udp_t, nread: isize, buf: ?*const c.uv_buf_t, sockaddr: ?*const c.sockaddr, _: c_uint) callconv(.C) void {
        // Received data on the libuv socket
        const this: *QuicConn = @alignCast(@ptrCast(handle.?.data));
        if (nread > 0) {
            std.log.info("quiche: received {} bytes", .{nread});
            const ret = c.quiche_conn_recv(this.quiche_conn, buf.?.base, @intCast(nread), &c.quiche_recv_info{
                .from = @constCast(sockaddr),
                .from_len = @sizeOf(c.sockaddr),
                .to = @ptrCast(&this.bound_sockaddr),
                .to_len = @sizeOf(c.sockaddr),
            });
            if (ret < 0) {
                std.log.err("quiche recv err {}", .{ret});
            }
        }
        if (nread == 0) {
            std.log.info("quiche: updating after recv", .{});
            this.quiche_update();
        }
        if (buf.?.base) |ptr| {
            std.heap.c_allocator.free(ptr[0..buf.?.len]);
        }
    }

    pub fn uv_alloc_impl(handle: ?*c.uv_handle_t, size: usize, buf: ?*c.uv_buf_t) callconv(.C) void {
        const this: *QuicConn = @alignCast(@ptrCast(handle.?.data));
        buf.?.base = null;
        buf.?.len = 0;
        const mem = this.allocator.alloc(u8, size) catch return;
        buf.?.base = mem.ptr;
        buf.?.len = mem.len;
    }
};

fn quic_on_established(uv_loop: *c.uv_loop_t) void {
    start_business(uv_loop) catch unreachable;
}

var g_pw_loop: pw.ThreadLoop = undefined;
var g_quic_conn: *QuicConn = undefined;

fn uv_output_notif_cb(_: ?*c.uv_async_t) callconv(.C) void {
    std.log.debug("enter uv_output_notif_cb", .{});
    g_output_m.lock();
    const slice = g_output_ringbuf.sliceAt(g_output_ringbuf.read_index, g_output_ringbuf.len());
    if (slice.first.len > 0) g_quic_conn.send(slice.first);
    if (slice.second.len > 0) g_quic_conn.send(slice.second);
    const wr_sum = slice.first.len + slice.second.len;
    g_quic_conn.quiche_update();
    g_output_ringbuf.read_index = g_output_ringbuf.mask2(g_output_ringbuf.read_index + slice.first.len + slice.second.len);
    g_output_m.unlock();
    std.log.debug("exit uv_output_notif_cb. consumed {} bytes", .{wr_sum});
}

fn start_business(uv_loop: *c.uv_loop_t) !void {
    const ally = std.heap.c_allocator;
    g_opus_encoder = c.opus_encoder_create(48000, 2, c.OPUS_APPLICATION_VOIP, null).?;

    if (c.uv_async_init(uv_loop, &g_output_notif, uv_output_notif_cb) < 0) {
        return error.UvError;
    }

    g_input_ringbuf = try std.RingBuffer.init(ally, 2 * 7680);
    g_output_ringbuf = try std.RingBuffer.init(ally, 4096);
    const thread = try std.Thread.spawn(.{}, input_encoder, .{ally});
    thread.detach();

    g_pw_loop = pw.ThreadLoop.new();
    const audio_format = pod.object(.format, 3, .{
        pod.prop(SpaFormatProps.MediaType, pod.id(SpaMediaType.Audio)),
        pod.prop(SpaFormatProps.MediaSubtype, pod.id(SpaMediaSubtype.Raw)),
        pod.prop(SpaFormatProps.AudioFormat, pod.id(283)),
        pod.prop(SpaFormatProps.AudioRate, pod.int(48000)),
        pod.prop(SpaFormatProps.AudioChannels, pod.int(2)),
    });
    const evt = try ally.create(pw.StreamEvents(MicrophoneStreamEvents));
    evt.* = pw.StreamEvents(MicrophoneStreamEvents).new(.{
        .id = "microphone",
    });
    const strm = pw.Stream.new(g_pw_loop.get_loop(), "Agora", .{
        .mediaType = .audio,
        .mediaCategory = .capture,
        .mediaRole = .communication,
    }, evt);
    evt.object.stream = strm;
    try strm.connect(.input, .{audio_format});

    try g_pw_loop.start();
}

pub fn main() !void {
    pw.init();

    const ally = std.heap.c_allocator;

    var uv_loop: c.uv_loop_t = undefined;
    if (c.uv_loop_init(&uv_loop) < 0) {
        return error.UvError;
    }

    const server_addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8443);
    g_quic_conn = try QuicConn.connect(ally, &uv_loop, server_addr, "localhost", QuicCallbacks(c.uv_loop_t){
        .object = &uv_loop,
        .on_established = quic_on_established,
    });

    if (c.uv_run(&uv_loop, c.UV_RUN_DEFAULT) < 0) {
        return error.UvError;
    }
}
