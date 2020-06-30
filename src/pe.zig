const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const fs = std.fs;

const coff = @import("./coff.zig");

// where the offset to the PE header is
const pe_signature_offset_position = 0x3c;

pub fn getPESignatureLocation(file: fs.File) !u32 {
    try file.seekTo(pe_signature_offset_position);
    var offset_buffer: [4]u8 = undefined;
    if ((try file.read(offset_buffer[0..])) != 4) return error.FileTooSmall;

    return mem.bytesToValue(u32, offset_buffer[0..]);
}
