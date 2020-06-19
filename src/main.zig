const std = @import("std");
const process = std.process;
const mem = std.mem;
const heap = std.heap;
const fs = std.fs;
const debug = std.debug;
const fmt = std.fmt;

const ArrayList = std.ArrayList;

// where the offset to the PE header is
const pe_offset_position = 0x3c;

const x64_tag = "\x64\x86";
const x86_tag = "\x4c\x01";

pub fn main() anyerror!void {
    var arg_iterator = process.ArgIterator.init();
    _ = arg_iterator.skip();

    var binary_paths = ArrayList([]const u8).init(heap.page_allocator);

    while (arg_iterator.next(heap.page_allocator)) |arg| {
        var binary_path = try arg;
        // cut off annoying prefix
        if (mem.eql(u8, binary_path[0..2], ".\\")) binary_path = binary_path[2..];
        try binary_paths.append(binary_path);
    }
    if (binary_paths.items.len == 0) {
        debug.warn("No binaries specified.\n", .{});

        process.exit(1);
    }

    const cwd = fs.cwd();
    for (binary_paths.items) |binary_path| {
        var binary_file = try cwd.openFile(binary_path, fs.File.OpenFlags{});
        defer binary_file.close();

        try binary_file.seekTo(pe_offset_position);
        var pe_tag_offset_bytes: [4]u8 = undefined;
        if ((try binary_file.read(pe_tag_offset_bytes[0..])) != 4) {
            debug.warn("Unable to read PE header start.\n", .{});

            process.exit(1);
        }

        const pe_tag_offset = mem.bytesToValue(u32, pe_tag_offset_bytes[0..]);
        try binary_file.seekTo(pe_tag_offset);
        var signature_buffer: [6]u8 = undefined;
        const bytes_read = try binary_file.read(signature_buffer[0..]);
        const tag_bytes = signature_buffer[0..4];

        if (bytes_read < 2 or !mem.eql(u8, tag_bytes, "PE\x00\x00")) {
            debug.warn("Weird binary, exiting.\n", .{});

            process.exit(1);
        } else {
            const architecture_bytes = signature_buffer[4..];
            const architecture_string = arch: {
                if (mem.eql(u8, architecture_bytes, x64_tag)) {
                    break :arch "x64";
                } else if (mem.eql(u8, architecture_bytes, x86_tag)) {
                    break :arch "x86";
                } else {
                    break :arch "Unknown";
                }
            };
            debug.warn("{}: {}\n", .{ binary_path, architecture_string });
        }
    }
}
