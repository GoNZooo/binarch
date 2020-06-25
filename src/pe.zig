const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const fs = std.fs;

// where the offset to the PE header is
const pe_offset_position = 0x3c;

const x64_tag = "\x64\x86";
const x86_tag = "\x4c\x01";

pub fn getPEHeaderLocation(file: fs.File) !u32 {
    try file.seekTo(pe_offset_position);
    var offset_buffer: [4]u8 = undefined;
    if ((try file.read(offset_buffer[0..])) != 4) return error.FileTooSmall;

    return mem.bytesToValue(u32, offset_buffer[0..]);
}

const MachineType = enum {
    x86,
    x64,
    unknown,
};

pub fn getMachineType(file: fs.File) !MachineType {
    const pe_tag_offset = try getPEHeaderLocation(file);
    try file.seekTo(pe_tag_offset);
    var signature_buffer: [6]u8 = undefined;
    const bytes_read = try file.read(signature_buffer[0..]);
    const tag_bytes = signature_buffer[0..4];

    if (bytes_read < 2 or !mem.eql(u8, tag_bytes, "PE\x00\x00")) {
        return error.NoPESignatureAtHeader;
    } else {
        const architecture_bytes = signature_buffer[4..];
        if (mem.eql(u8, architecture_bytes, x64_tag)) {
            return MachineType.x64;
        } else if (mem.eql(u8, architecture_bytes, x86_tag)) {
            return MachineType.x86;
        } else {
            return MachineType.unknown;
        }
    }
}

pub fn getMachineTypeForPath(directory: fs.Dir, path: []const u8) !MachineType {
    var file = try directory.openFile(path, fs.File.OpenFlags{});
    defer file.close();
    return try getMachineType(file);
}
