const AtomicRingBuffer = @This();
const std = @import("std");

pub const Error = error{ NotEnoughData, Full };

data: []u8,
read: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
write: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

pub fn init(allocator: std.mem.Allocator, size: usize) !AtomicRingBuffer {
    const data = try allocator.alloc(u8, size);
    return .{
        .data = data,
    };
}

pub fn deinit(this: *AtomicRingBuffer, allocator: std.mem.Allocator) void {
    allocator.free(this.data);
}

pub fn writeSlice(this: *AtomicRingBuffer, bytes: []const u8) Error!void {
    const read = this.read.load(.seq_cst);
    const write = this.write.load(.seq_cst);

    if (write >= read) {
        // +--------+------------+--------+
        // |        | ## DATA ## |        |
        // +--------+------------+--------+
        //     read ^            ^ write
        const available_space = (this.data.len - write) + read;
        if (bytes.len > available_space) return Error.Full;

        const end_len = @min(this.data.len - write, bytes.len);
        const start_len = @min(bytes.len - end_len, read);
        @memcpy(this.data[write .. write + end_len], bytes[0..end_len]);
        @memcpy(this.data[0..start_len], bytes[end_len .. end_len + start_len]);
        if (start_len == 0) {
            this.write.store(write + end_len, .seq_cst);
        } else {
            this.write.store(start_len, .seq_cst);
        }
    } else {
        // +------------+--------+------------+
        // | ## DATA ## |        | ## DATA ## |
        // +------------+--------+------------+
        //        write ^        ^ read
        const available_space = read - write;
        if (bytes.len > available_space) return Error.Full;

        const write_len = @min(available_space, bytes.len);
        @memcpy(this.data[read .. read + write_len], bytes[0..write_len]);
        this.write.store(read + write_len, .seq_cst);
    }
}

pub fn readSlice(this: *AtomicRingBuffer, bytes: []u8) Error!void {
    const read = this.read.load(.seq_cst);
    const write = this.write.load(.seq_cst);

    if (write >= read) {
        // +--------+------------+--------+
        // |        | ## DATA ## |        |
        // +--------+------------+--------+
        //     read ^            ^ write
        const available = write - read;
        if (bytes.len > available) return Error.NotEnoughData;

        const copy_amt = @min(available, bytes.len);
        @memcpy(bytes, this.data[read .. read + copy_amt]);
        this.read.store(read + copy_amt, .seq_cst);
    } else {
        // +------------+--------+------------+
        // | ## DATA ## |        | ## DATA ## |
        // +------------+--------+------------+
        //        write ^        ^ read
        const available = write + (this.data.len - read);
        if (bytes.len > available) return Error.NotEnoughData;

        const end_len = @min(this.data.len - read, bytes.len);
        const start_len = @min(bytes.len - end_len, write);
        @memcpy(bytes[0..end_len], this.data[read .. read + end_len]);
        @memcpy(bytes[end_len .. end_len + start_len], this.data[0..start_len]);
        if (start_len == 0) {
            this.read.store(read + end_len, .seq_cst);
        } else {
            this.read.store(start_len, .seq_cst);
        }
    }
}

test "simple writes and reads" {
    var rb = try init(std.testing.allocator, 5);
    defer rb.deinit(std.testing.allocator);

    try rb.writeSlice(&[5]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee });
    var readData: [5]u8 = undefined;
    try rb.readSlice(&readData);
    std.debug.assert(std.mem.eql(u8, &readData, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee }));
}

test "overflowing writes and reads" {
    var rb = try init(std.testing.allocator, 5);
    defer rb.deinit(std.testing.allocator);

    try rb.writeSlice(&[3]u8{ 0x11, 0x22, 0x33 });
    var readData: [3]u8 = undefined;
    try rb.readSlice(&readData);
    std.debug.assert(std.mem.eql(u8, &readData, &[_]u8{ 0x11, 0x22, 0x33 }));

    try rb.writeSlice(&[3]u8{ 0x44, 0x55, 0x66 });
    try rb.readSlice(&readData);
    std.debug.assert(std.mem.eql(u8, &readData, &[_]u8{ 0x44, 0x55, 0x66 }));
}

test "overflowing writes and reads (2)" {
    var rb = try init(std.testing.allocator, 6);
    defer rb.deinit(std.testing.allocator);

    // move pointers to middle to have overflow
    try rb.writeSlice(&[3]u8{ 0xaa, 0xbb, 0xcc });
    var readData: [3]u8 = undefined;
    try rb.readSlice(&readData);
    std.debug.assert(std.mem.eql(u8, &readData, &[_]u8{ 0xaa, 0xbb, 0xcc }));

    try rb.writeSlice(&[3]u8{ 0x11, 0x22, 0x33 });
    try rb.writeSlice(&[3]u8{ 0x44, 0x55, 0x66 });

    try rb.readSlice(&readData);
    std.debug.assert(std.mem.eql(u8, &readData, &[_]u8{ 0x11, 0x22, 0x33 }));
    try rb.readSlice(&readData);
    std.debug.assert(std.mem.eql(u8, &readData, &[_]u8{ 0x44, 0x55, 0x66 }));
}
