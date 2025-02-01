const std = @import("std");

pub const Error = error{DBusError} || std.Thread.SpawnError;

extern fn dbus_threads_init(functions: ?*const anyopaque) void;
pub fn init_threads() void {
    dbus_threads_init(null);
}

const DBusConnection = opaque {};
const DBusHandlerResult = enum(c_int) { handled, not_yet_handled, need_memory };
const DBusMessage = opaque {};

pub const Message = struct {
    raw: *DBusMessage,

    const Self = @This();

    extern fn dbus_message_get_path(message: *DBusMessage) ?[*:0]const u8;
    extern fn dbus_message_get_member(message: *DBusMessage) ?[*:0]const u8;
    extern fn dbus_message_get_interface(message: *DBusMessage) ?[*:0]const u8;
    extern fn dbus_message_new_method_call(target: [*:0]const u8, object: [*:0]const u8, interface: [*:0]const u8, method: [*:0]const u8) ?*DBusMessage;
    const DBusMessageIter = extern struct {
        f1: ?*anyopaque,
        f2: ?*anyopaque,
        f3: u32,
        f4: c_int,
        f5: c_int,
        f6: c_int,
        f7: c_int,
        f8: c_int,
        f9: c_int,
        f10: c_int,
        f11: c_int,
        f12: c_int,
        f13: ?*anyopaque,
        f14: ?*anyopaque,
    };
    extern fn dbus_message_iter_init_append(message: *DBusMessage, iter: *DBusMessageIter) void;

    pub fn new_method_call(target: [:0]const u8, object: [:0]const u8, interface: [:0]const u8, method: [:0]const u8) Error!Self {
        const raw = dbus_message_new_method_call(target.ptr, object.ptr, interface.ptr, method.ptr) orelse return Error.DBusError;
        return .{ .raw = raw };
    }

    pub fn get_path(self: Self) ?[]const u8 {
        const path = dbus_message_get_path(self.raw) orelse return null;
        return std.mem.span(path);
    }

    pub fn get_member(self: Self) ?[]const u8 {
        const path = dbus_message_get_member(self.raw) orelse return null;
        return std.mem.span(path);
    }

    pub fn get_interface(self: Self) ?[]const u8 {
        const path = dbus_message_get_interface(self.raw) orelse return null;
        return std.mem.span(path);
    }

    extern fn dbus_message_iter_open_container(iter: *DBusMessageIter, type: c_int, signature: ?[*:0]const u8, sub: *DBusMessageIter) bool;
    extern fn dbus_message_iter_append_basic(iter: *DBusMessageIter, type: c_int, ptr: *const anyopaque) bool;
    extern fn dbus_message_iter_close_container(iter: *DBusMessageIter, sub: *DBusMessageIter) bool;

    pub const DictBuilder = struct {
        parent: *DBusMessageIter,
        raw: DBusMessageIter,

        pub fn string(self: *@This(), key: [:0]const u8, value: [:0]const u8) Error!void {
            var entry: DBusMessageIter = undefined;
            if (!dbus_message_iter_open_container(&self.raw, 'e', null, &entry)) {
                return Error.DBusError;
            }
            errdefer _ = dbus_message_iter_close_container(&self.raw, &entry);

            if (!dbus_message_iter_append_basic(&entry, 's', @ptrCast(&key.ptr))) {
                return Error.DBusError;
            }
            try variant_basic(&entry, 's', @ptrCast(&value.ptr));

            if (!dbus_message_iter_close_container(&self.raw, &entry)) {
                return Error.DBusError;
            }
        }

        pub fn close(self: *@This()) Error!void {
            if (!dbus_message_iter_close_container(self.parent, &self.raw)) {
                return Error.DBusError;
            }
        }

        fn variant_basic(entry: *DBusMessageIter, var_type: u8, ptr: *const anyopaque) Error!void {
            var variant: DBusMessageIter = undefined;
            if (!dbus_message_iter_open_container(entry, 'v', &.{var_type}, &variant)) {
                return Error.DBusError;
            }
            errdefer _ = dbus_message_iter_close_container(entry, &variant);

            if (!dbus_message_iter_append_basic(&variant, var_type, ptr)) {
                return Error.DBusError;
            }

            if (!dbus_message_iter_close_container(entry, &variant)) {
                return Error.DBusError;
            }
        }
    };

    pub const ArgsBuilder = struct {
        raw: DBusMessageIter,

        pub fn dict(self: *@This()) Error!DictBuilder {
            var sub: DBusMessageIter = undefined;
            if (!dbus_message_iter_open_container(&self.raw, 'a', "{sv}", &sub)) {
                return Error.DBusError;
            }

            return .{ .parent = &self.raw, .raw = sub };
        }
    };

    pub fn append_args(self: Self) ArgsBuilder {
        var iter: DBusMessageIter = undefined;
        dbus_message_iter_init_append(self.raw, &iter);
        return .{ .raw = iter };
    }
};

pub fn MessageFilter(T: type) type {
    return struct {
        object: *T,

        pub fn new(ptr: *T) @This() {
            return .{ .object = ptr };
        }

        fn handle_raw(conn_raw: *DBusConnection, msg_raw: *DBusMessage, user_data: ?*anyopaque) callconv(.C) DBusHandlerResult {
            const object: *T = @alignCast(@ptrCast(user_data.?));
            object.handle_message(Connection{ .raw = conn_raw }, Message{ .raw = msg_raw });
            return .not_yet_handled;
        }

        fn free_raw(user_data: ?*anyopaque) callconv(.C) void {
            if (@hasDecl(T, "deinit")) {
                const object: *T = @alignCast(@ptrCast(user_data.?));
                object.deinit();
            }
        }
    };
}

pub const Connection = struct {
    raw: *DBusConnection,
    const Self = @This();

    // External
    const DBusError = extern struct {
        name: ?[*:0]const u8,
        message: ?[*:0]const u8,
        dummy: u8,
        padding1: ?*anyopaque,
    };
    extern fn dbus_error_init(this: *DBusError) void;
    extern fn dbus_error_free(this: *DBusError) void;

    const DBusBusType = enum(c_int) { session, system, starter };
    extern fn dbus_bus_get(bus_type: DBusBusType, err: ?*DBusError) ?*DBusConnection;
    extern fn dbus_bus_get_unique_name(conn: *DBusConnection) ?[*:0]const u8;
    extern fn dbus_connection_read_write_dispatch(conn: *DBusConnection, timeout_millis: c_int) bool;
    extern fn dbus_bus_add_match(conn: *DBusConnection, rule: [*:0]const u8, err: ?*DBusError) void;
    const DBusHandleMessageFunction = *const fn (conn: *DBusConnection, message: *DBusMessage, user_data: ?*anyopaque) callconv(.C) DBusHandlerResult;
    const DBusFreeFunction = *const fn (user_data: ?*anyopaque) callconv(.C) void;
    extern fn dbus_connection_add_filter(conn: *DBusConnection, function: DBusHandleMessageFunction, user_data: *anyopaque, free_data_function: DBusFreeFunction) void;
    extern fn dbus_connection_send(conn: *DBusConnection, message: *DBusMessage, serial: ?*u32) bool;

    pub fn open_session_bus() Error!Self {
        const maybe_conn = dbus_bus_get(.session, null);
        const conn = maybe_conn orelse return Error.DBusError;
        return .{ .raw = conn };
    }

    pub fn get_id(self: Self) Error![]const u8 {
        const raw = dbus_bus_get_unique_name(self.raw) orelse return Error.DBusError;
        return std.mem.span(raw);
    }

    pub fn add_match_rule(self: Self, rule: [:0]const u8) void {
        dbus_bus_add_match(self.raw, rule.ptr, null);
    }

    pub fn add_filter(self: Self, filter: anytype) void {
        _ = dbus_connection_add_filter(self.raw, @TypeOf(filter).handle_raw, filter.object, @TypeOf(filter).free_raw);
    }

    pub fn send(self: Self, message: Message) Error!u32 {
        var serial: u32 = undefined;
        if (!dbus_connection_send(self.raw, message.raw, &serial)) {
            return Error.DBusError;
        }
        return serial;
    }

    pub fn start_threadloop(self: Self) Error!void {
        const thread = try std.Thread.spawn(.{}, threadloop_inner, .{self});
        thread.detach();
    }

    fn threadloop_inner(self: Self) void {
        while (dbus_connection_read_write_dispatch(self.raw, -1)) {}
    }
};
