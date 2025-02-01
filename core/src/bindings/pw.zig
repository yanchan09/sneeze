const std = @import("std");

const Error = error{ PipewireError, OutOfBuffers };

extern fn pw_init(argc: ?*c_int, argv: ?*[*:null]?[*:0]const u8) void;
extern fn pw_deinit() void;

pub fn init() void {
    pw_init(null, null);
}

const pw_loop = opaque {};

pub const ThreadLoop = struct {
    raw: *pw_thread_loop,

    const Self = @This();

    // External definitions
    const pw_thread_loop = opaque {};

    extern fn pw_thread_loop_new(name: ?[*:0]const u8, props: ?*anyopaque) *pw_thread_loop;
    extern fn pw_thread_loop_destroy(loop: *pw_thread_loop) void;
    extern fn pw_thread_loop_start(loop: *pw_thread_loop) c_int;
    extern fn pw_thread_loop_stop(loop: *pw_thread_loop) void;
    extern fn pw_thread_loop_lock(loop: *pw_thread_loop) void;
    extern fn pw_thread_loop_unlock(loop: *pw_thread_loop) void;
    extern fn pw_thread_loop_get_loop(loop: *pw_thread_loop) *pw_loop;

    pub fn new() Self {
        const raw = pw_thread_loop_new(null, null);
        return .{ .raw = raw };
    }

    pub fn start(self: Self) Error!void {
        if (pw_thread_loop_start(self.raw) < 0) {
            return Error.PipewireError;
        }
    }

    pub fn stop(self: Self) void {
        pw_thread_loop_stop(self.raw);
    }

    pub fn deinit(self: Self) void {
        pw_thread_loop_destroy(self.raw);
    }

    pub fn get_loop(self: Self) *pw_loop {
        return pw_thread_loop_get_loop(self.raw);
    }
};

const spa_meta = extern struct {
    type: u32,
    size: u32,
    data: ?*anyopaque,
};

const spa_chunk = extern struct {
    offset: u32,
    size: u32,
    stride: i32,
    flags: i32,
};

const spa_data = extern struct {
    type: u32,
    flags: u32,
    fd: i64,
    mapoffset: u32,
    maxsize: u32,
    data: ?[*]u8,
    chunk: *spa_chunk,
};

const spa_buffer = extern struct {
    n_metas: u32,
    n_datas: u32,
    metas: [*]spa_meta,
    datas: [*]spa_data,
};

const pw_buffer = extern struct {
    buffer: *spa_buffer,
    user_data: ?*anyopaque,
    size: u64,
    requested: u64,
    time: u64,
};

const pw_stream_state = enum(c_int) {
    @"error" = -1,
    unconnected = 0,
    connecting = 1,
    paused = 2,
    streaming = 3,
};

const pw_stream_control = extern struct {
    name: [*:0]const u8,
    flags: u32,
    def: f32,
    min: f32,
    max: f32,
    values: [*]f32,
    n_values: u32,
    max_values: u32,
};

const spa_pod = extern struct {
    size: u32,
    type: u32,
};

const pw_stream_events = extern struct {
    version: u32 = 2,
    destroy: ?*const fn (?*anyopaque) callconv(.C) void = null,
    state_changed: ?*const fn (?*anyopaque, pw_stream_state, pw_stream_state, ?[*:0]const u8) callconv(.C) void = null,
    control_info: ?*const fn (?*anyopaque, u32, *const pw_stream_control) callconv(.C) void = null,
    io_changed: ?*const fn (?*anyopaque, u32, ?*anyopaque, u32) callconv(.C) void = null,
    param_changed: ?*const fn (?*anyopaque, u32, *const spa_pod) callconv(.C) void = null,
    add_buffer: ?*const fn (?*anyopaque, *pw_buffer) callconv(.C) void = null,
    remove_buffer: ?*const fn (?*anyopaque, *pw_buffer) callconv(.C) void = null,
    process: ?*const fn (?*anyopaque) callconv(.C) void = null,
    drained: ?*const fn (?*anyopaque) callconv(.C) void = null,
    command: ?*const fn (?*anyopaque, *anyopaque) callconv(.C) void = null,
    trigger_done: ?*const fn (?*anyopaque) callconv(.C) void = null,
};

// const spa_dict_item = extern struct {
//     key: [*:0]const u8,
//     value: [*:0]const u8,
// };
//
// const spa_dict = extern struct {
//     flags: u32 = 0,
//     n_items: u32,
//     items: [*]const spa_dict_item,
// };
//
// const pw_properties = extern struct {
//     dict: spa_dict,
//     flags: u32 = 0,
// };
const pw_properties = opaque {};

extern fn pw_properties_new(...) *pw_properties;

pub fn StreamEvents(T: type) type {
    return struct {
        object: T,
        param_changed: ?*const fn (self: *T, id: u32, param: [*]const u8) void = null,
        process: ?*const fn (self: *T) void = null,

        const Self = @This();

        pub fn new(events: T) Self {
            var this: Self = .{
                .object = events,
            };
            if (@hasDecl(T, "param_changed")) {
                this.param_changed = T.param_changed;
            }
            if (@hasDecl(T, "process")) {
                this.process = T.process;
            }
            return this;
        }

        fn _global_param_changed(data: ?*anyopaque, id: u32, param: *const spa_pod) callconv(.C) void {
            const se: *StreamEvents(T) = @alignCast(@ptrCast(data.?));
            if (se.param_changed) |cb| cb(&se.object, id, @ptrCast(param));
        }

        fn _global_process(data: ?*anyopaque) callconv(.C) void {
            const se: *StreamEvents(T) = @alignCast(@ptrCast(data.?));
            if (se.process) |cb| cb(&se.object);
        }

        fn get_raw(_: Self) *const pw_stream_events {
            return &.{
                .param_changed = _global_param_changed,
                .process = _global_process,
            };
        }
    };
}

pub const AudioFormat = enum(c_int) {
    f32 = 283,
};

const spa_pod_builder = extern struct {
    const spa_callbacks = extern struct {
        funcs: ?*const anyopaque = null,
        data: ?*anyopaque = null,
    };

    const spa_pod_builder_state = extern struct {
        offset: u32 = 0,
        flags: u32 = 0,
        frame: ?*anyopaque = null,
    };

    data: [*]u8,
    size: u32,
    _padding: u32 = 0,
    state: spa_pod_builder_state = .{},
    callbacks: spa_callbacks = .{},
};

const spa_type = enum(u32) {
    none = 1,
    bool = 2,
    id = 3,
    int = 4,
    long = 5,
    float = 6,
    double = 7,
    string = 8,
    bytes = 9,
    rectangle = 10,
    fraction = 11,
    bitmap = 12,
    array = 13,
    @"struct" = 14,
    object = 15,
    sequence = 16,
    pointer = 17,
    fd = 18,
    choice = 19,
    pod = 20,
};

pub const AudioInfo = struct {
    format: AudioFormat,
    rate: u32,
    channels: u32,

    const Self = @This();

    const spa_audio_info_raw = extern struct {
        format: AudioFormat,
        flags: u32 = 0,
        rate: u32,
        channels: u32,
        position: [64]u32 = std.mem.zeroes([64]u32),
    };
};

pub const Stream = struct {
    raw: *pw_stream,

    const Self = @This();

    // note: must be compatible with pw_direction
    const Direction = enum(c_uint) {
        input = 0,
        output = 1,
    };

    const Properties = struct {
        const MediaType = enum {
            audio,
            video,
            midi,

            fn as_string(self: @This()) [:0]const u8 {
                return switch (self) {
                    .audio => "Audio",
                    .video => "Video",
                    .midi => "Midi",
                };
            }
        };

        const MediaCategory = enum {
            playback,
            capture,
            duplex,
            monitor,
            manager,

            fn as_string(self: @This()) [:0]const u8 {
                return switch (self) {
                    .playback => "Playback",
                    .capture => "Capture",
                    .duplex => "Duplex",
                    .monitor => "Monitor",
                    .manager => "Manager",
                };
            }
        };

        const MediaRole = enum {
            movie,
            music,
            camera,
            screen,
            communication,
            game,
            notification,
            dsp,
            production,
            accessibility,
            @"test",

            fn as_string(self: @This()) [:0]const u8 {
                return switch (self) {
                    .movie => "Movie",
                    .music => "Music",
                    .camera => "Camera",
                    .screen => "Screen",
                    .communication => "Communication",
                    .game => "Game",
                    .notification => "Notification",
                    .dsp => "DSP",
                    .production => "Production",
                    .accessibility => "Accessibility",
                    .@"test" => "Test",
                };
            }
        };

        mediaType: MediaType,
        mediaCategory: MediaCategory,
        mediaRole: MediaRole,
    };

    // External definitions
    const pw_stream = opaque {};
    extern fn pw_stream_new_simple(loop: *pw_loop, name: [*:0]const u8, props: *const pw_properties, events: *const pw_stream_events, data: ?*anyopaque) *pw_stream;
    extern fn pw_stream_destroy(stream: *pw_stream) void;
    extern fn pw_stream_dequeue_buffer(stream: *pw_stream) ?*pw_buffer;
    extern fn pw_stream_queue_buffer(stream: *pw_stream, buffer: *pw_buffer) c_int;

    const pw_stream_flags = packed struct(c_uint) {
        autoconnect: bool = false,
        inactive: bool = false,
        map_buffers: bool = false,
        driver: bool = false,
        rt_process: bool = false,
        no_convert: bool = false,
        exclusive: bool = false,
        dont_reconnect: bool = false,
        alloc_buffers: bool = false,
        trigger: bool = false,
        @"async": bool = false,
        early_process: bool = false,
        rt_trigger_done: bool = false,
        _: u19 = 0,
    };
    extern fn pw_stream_connect(stream: *pw_stream, direction: Direction, target_id: u32, flags: pw_stream_flags, params: [*][*]const u8, n_params: u32) c_int;

    /// events must be alive until the stream is destroyed.
    pub fn new(loop: *pw_loop, name: [:0]const u8, properties: Properties, events: anytype) Self {
        const raw_properties = @call(.auto, pw_properties_new, .{
            @as([*:0]const u8, "media.type"),     properties.mediaType.as_string().ptr,
            @as([*:0]const u8, "media.category"), properties.mediaCategory.as_string().ptr,
            @as([*:0]const u8, "media.role"),     properties.mediaRole.as_string().ptr,
            @as(?[*:0]const u8, null),
        });
        const raw = pw_stream_new_simple(loop, name.ptr, raw_properties, events.get_raw(), events);
        return .{ .raw = raw };
    }

    pub fn connect(self: Self, direction: Direction, params: anytype) Error!void {
        const n_params = comptime blk: {
            var n_params: u32 = 0;
            for (params) |_| {
                n_params += 1;
            }
            break :blk n_params;
        };

        var raw_params: [n_params][*]const u8 = undefined;
        inline for (params, 0..) |p, i| {
            raw_params[i] = &p;
        }

        const PW_ID_ANY = @as(u32, 0xffffffff);
        if (pw_stream_connect(self.raw, direction, PW_ID_ANY, .{ .autoconnect = true, .map_buffers = true }, &raw_params, n_params) < 0) {
            return Error.PipewireError;
        }
    }

    pub fn dequeue_buffer(self: Self) Error!*pw_buffer {
        return pw_stream_dequeue_buffer(self.raw) orelse return Error.OutOfBuffers;
    }

    pub fn queue_buffer(self: Self, buffer: *pw_buffer) Error!void {
        if (pw_stream_queue_buffer(self.raw, buffer) < 0) {
            return Error.PipewireError;
        }
    }

    pub fn deinit(self: Self) void {
        pw_stream_destroy(self.raw);
    }
};
