const std = @import("std");
const c = @cImport({
    @cInclude("opus/opus.h");
    @cInclude("uv.h");
});

const AudioCaptureStream = @This();

encoder: ?*c.OpusEncoder = null,
uv_async_encoded_avail: c.uv_async_t,

pub fn init(allocator: std.mem.Allocator, uv_loop: *c.uv_loop_t) !void {
    const this = try allocator.create(AudioCaptureStream);
    errdefer allocator.destroy(this);
    this.* = .{
        .uv_async_encoded_avail = undefined,
    };

    // this.encoder = c.opus_encoder_create(48000, 2, c.OPUS_APPLICATION_VOIP, null).?;
    // errdefer c.opus_encoder_destroy(this.encoder);

    //if (c.uv_async_init(uv_loop, &this.uv_async_encoded_avail, uv_output_notif_cb) < 0) {
    //    return error.UvError;
    //}

    g_input_ringbuf = try std.RingBuffer.init(ally, 2 * 7680);
    g_output_ringbuf = try AtomicRingBuffer.init(ally, 4096);
    const thread = try std.Thread.spawn(.{}, input_encoder, .{ally});
    thread.detach();

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
}
