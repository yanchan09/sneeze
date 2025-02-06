const std = @import("std");

var g_log_timer: ?std.time.Timer = null;

pub fn init() !void {
    g_log_timer = try std.time.Timer.start();
}

pub fn logFn(comptime level: std.log.Level, comptime scope: @Type(.EnumLiteral), comptime format: []const u8, args: anytype) void {
    var bw = std.io.bufferedWriter(std.io.getStdErr().writer());
    const writer = bw.writer();

    var elapsed = g_log_timer.?.read();
    const ts_hour = elapsed / std.time.ns_per_hour;
    elapsed %= std.time.ns_per_hour;
    const ts_min = elapsed / std.time.ns_per_min;
    elapsed %= std.time.ns_per_min;
    const ts_sec = elapsed / std.time.ns_per_s;
    elapsed %= std.time.ns_per_s;
    const ts_msec = elapsed / std.time.ns_per_ms;

    const level_str = switch (level) {
        .err => "ERR",
        .warn => "WRN",
        .info => "INF",
        .debug => "DBG",
    };

    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    writer.print("{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3} {s}({s}): ", .{ ts_hour, ts_min, ts_sec, ts_msec, level_str, @tagName(scope) }) catch return;
    writer.print(format ++ "\n", args) catch return;
    bw.flush() catch return;
}
