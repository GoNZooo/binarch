const std = @import("std");
const process = std.process;
const mem = std.mem;
const heap = std.heap;
const fs = std.fs;
const debug = std.debug;
const fmt = std.fmt;

// where the offset to the PE header is
const pe_offset_position = 0x3c;

const x64_tag = "\x64\x86";
const x86_tag = "\x4c\x01";

fn getPEHeaderLocation(file: fs.File) !u32 {
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

fn getMachineType(file: fs.File) !MachineType {
    const pe_tag_offset = try getPEHeaderLocation(file);
    try file.seekTo(pe_tag_offset);
    var signature_buffer: [6]u8 = undefined;
    const bytes_read = try file.read(signature_buffer[0..]);
    const tag_bytes = signature_buffer[0..4];

    if (bytes_read < 2 or !mem.eql(u8, tag_bytes, "PE\x00\x00")) {
        debug.warn("Weird binary, exiting.\n", .{});

        process.exit(1);
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

fn getMachineTypeForPath(directory: fs.Dir, path: []const u8) !MachineType {
    var file = try directory.openFile(path, fs.File.OpenFlags{});
    defer file.close();
    return try getMachineType(file);
}

pub fn main() anyerror!void {
    var arg_iterator = process.ArgIterator.init();
    _ = arg_iterator.skip();

    const cwd = fs.cwd();
    while (arg_iterator.next(heap.page_allocator)) |arg| {
        var binary_path = try arg;
        // cut off annoying prefix
        if (mem.eql(u8, binary_path[0..2], ".\\")) binary_path = binary_path[2..];
        const machine_type = try getMachineTypeForPath(cwd, binary_path);
        const s = switch (machine_type) {
            .x64 => "x64",
            .x86 => "x86",
            .unknown => "unknown",
        };
        debug.warn("{}: {}\n", .{ binary_path, s });
    }
}
