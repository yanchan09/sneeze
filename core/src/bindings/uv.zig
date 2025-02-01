pub const uv_object = [*]align(8) u8;

pub const uv_run_mode = enum(c_int) {
    default = 0,
    once = 1,
    nowait = 2,
};
pub const uv_handle_type = enum(c_int) {
    unknown = 0,
    @"async" = 1,
    check = 2,
    fs_event = 3,
    fs_poll = 4,
    handle = 5,
    idle = 6,
    named_pipe = 7,
    poll = 8,
    prepare = 9,
    process = 10,
    stream = 11,
    tcp = 12,
    timer = 13,
    tty = 14,
    udp = 15,
    signal = 16,
    file = 17,
};

pub const uv_async_t = struct {};

/// Returns the size of the uv_loop_t structure.
pub extern fn uv_loop_size() usize;

/// Initializes the given uv_loop_t structure.
pub extern fn uv_loop_init(loop: uv_object) c_int;

pub extern fn uv_run(loop: uv_object, mode: uv_run_mode) c_int;

/// Releases all internal loop resources. Call this function only when the loop has finished executing and all open handles and requests have been closed, or it will return UV_EBUSY. After this function returns, the user can free the memory allocated for the loop.
pub extern fn uv_loop_close(loop: uv_object) c_int;

pub extern fn uv_handle_size(handle_type: uv_handle_type) usize;

pub const uv_async_cb = *const fn (handle: uv_object) callconv(.C) void;
pub extern fn uv_async_init(loop: uv_object, handle: uv_object, async_cb: uv_async_cb) c_int;
pub extern fn uv_async_send(handle: uv_object) c_int;

pub extern fn uv_handle_get_data(handle: uv_object) ?*anyopaque;
pub extern fn uv_handle_set_data(handle: uv_object, data: ?*anyopaque) void;
