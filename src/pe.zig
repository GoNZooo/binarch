const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const fs = std.fs;

const coff = @import("./coff.zig");

// where the offset to the PE header is
pub const pe_signature_offset_position = 0x3c;

pub fn getPESignatureLocation(buffer: []const u8) !u32 {
    if (buffer.len < (pe_signature_offset_position + 4)) return error.BufferTooSmall;

    return mem.bytesToValue(
        u32,
        buffer[pe_signature_offset_position..(pe_signature_offset_position + 4)],
    );
}
