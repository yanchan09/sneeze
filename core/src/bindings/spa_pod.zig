const std = @import("std");

pub const ObjectType = enum(u32) {
    param_buffers = 0x40004,
    format = 262147,
};

pub fn int(value: u32) [16]u8 {
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 4, .little);
    std.mem.writeInt(u32, buf[4..8], 4, .little);
    std.mem.writeInt(u32, buf[8..12], value, .little);
    std.mem.writeInt(u32, buf[12..16], 0, .little);
    return buf;
}

pub fn id(value: u32) [16]u8 {
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 4, .little);
    std.mem.writeInt(u32, buf[4..8], 3, .little);
    std.mem.writeInt(u32, buf[8..12], value, .little);
    std.mem.writeInt(u32, buf[12..16], 0, .little);
    return buf;
}

pub fn rectangle(width: u32, height: u32) [16]u8 {
    var buf: [16]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], 8, .little);
    std.mem.writeInt(u32, buf[4..8], 10, .little);
    std.mem.writeInt(u32, buf[8..12], width, .little);
    std.mem.writeInt(u32, buf[12..16], height, .little);
    return buf;
}

pub fn prop(prop_id: u32, value: anytype) [8 + value.len]u8 {
    var buf: [8 + value.len]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], prop_id, .little);
    std.mem.writeInt(u32, buf[4..8], 0, .little);
    @memcpy(buf[8..], value[0..]);
    return buf;
}

fn object_size(properties: std.builtin.Type) u32 {
    var sz: u32 = 16;
    for (properties.Struct.fields) |field| {
        sz += @sizeOf(field.type);
    }
    return sz;
}

pub fn object(object_type: ObjectType, object_id: u32, properties: anytype) [object_size(@typeInfo(@TypeOf(properties)))]u8 {
    const sz = comptime object_size(@typeInfo(@TypeOf(properties)));
    var buf: [sz]u8 = undefined;
    std.mem.writeInt(u32, buf[0..4], sz - 8, .little);
    std.mem.writeInt(u32, buf[4..8], 15, .little);
    std.mem.writeInt(u32, buf[8..12], @intFromEnum(object_type), .little);
    std.mem.writeInt(u32, buf[12..16], object_id, .little);

    // write out properties
    var offs: usize = 16;
    inline for (properties) |this_prop| {
        @memcpy(buf[offs .. offs + this_prop.len], this_prop[0..]);
        offs += this_prop.len;
    }
    return buf;
}
