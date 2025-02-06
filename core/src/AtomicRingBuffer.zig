const AtomicRingBuffer = @This();
const std = @import("std");

pub const Error = error{Full};

data: []u8,
read: std.atomic.Value(usize),
write: std.atomic.Value(usize),

pub fn writeSlice(this: *AtomicRingBuffer, bytes: []const u8) Error!void {
    const read = this.read.load(.seq_cst);
    const write = this.write.load(.seq_cst);

    if (write >= read) {
        const available_space = (this.data.len - write) + read;
        if (bytes.len > available_space) return Error.Full;

        const end_len = @min(this.data.len - write, bytes.len);
        const start_len = @min(bytes.len - end_len, read);
        @memcpy(this.data[write .. write + end_len], bytes[0..end_len]);
        @memcpy(this.data[0..start_len], bytes[end_len .. end_len + start_len]);
    } else {
        const available_space = read - write;
        if (bytes.len > available_space) return Error.Full;

        const write_len = @min(available_space, bytes.len);
        @memcpy(this.data[read .. read + write_len], bytes[0..write_len]);
        this.write.store(read + write_len, .seq_cst);
    }
}

pub fn readSlice(this: *AtomicRingBuffer, bytes: []u8) Error!void {

}
