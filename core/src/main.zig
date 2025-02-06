const logger = @import("./logger.zig");
pub const std_options = .{ .logFn = logger.logFn };

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

pub const QuicConn = @import("./QuicConn.zig");

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
    try logger.init();
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
