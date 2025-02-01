pub const pa_context = opaque {};
pub const pa_mainloop_api = opaque {};
pub const pa_threaded_mainloop = opaque {};

pub const pa_context_notify_cb_t = *const fn (c: *pa_context, userdata: ?*anyopaque) callconv(.C) void;

pub const pa_context_state = enum(c_int) {
    unconnected,
    connecting,
    authorizing,
    setting_name,
    ready,
    failed,
    terminated,
};

pub extern fn pa_context_new(mainloop: *const pa_mainloop_api, name: [*:0]const u8) *pa_context;
pub extern fn pa_context_connect(c: *pa_context, server: ?[*:0]const u8, flags: c_int, api: ?*anyopaque) c_int;
pub extern fn pa_context_set_state_callback(c: *pa_context, cb: pa_context_notify_cb_t, userdata: ?*anyopaque) c_int;
pub extern fn pa_context_disconnect(c: *pa_context) void;
pub extern fn pa_context_get_state(c: *pa_context) pa_context_state;
pub extern fn pa_context_unref(c: *pa_context) void;

pub extern fn pa_threaded_mainloop_new() *pa_threaded_mainloop;
pub extern fn pa_threaded_mainloop_free(m: *pa_threaded_mainloop) void;
pub extern fn pa_threaded_mainloop_lock(m: *pa_threaded_mainloop) void;
pub extern fn pa_threaded_mainloop_start(m: *pa_threaded_mainloop) c_int;
pub extern fn pa_threaded_mainloop_unlock(m: *pa_threaded_mainloop) void;
pub extern fn pa_threaded_mainloop_get_api(m: *pa_threaded_mainloop) *const pa_mainloop_api;
