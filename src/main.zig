const std = @import("std");
const process = std.process;
const mem = std.mem;
const heap = std.heap;
const fs = std.fs;
const debug = std.debug;

// where the offset to the PE header is
const pe_offset_position = 0x3c;

pub fn main() anyerror!void {
    var arg_iterator = process.ArgIterator.init();
    _ = arg_iterator.next(heap.page_allocator);
    const maybe_binary_path = arg_iterator.next(heap.page_allocator);
    if (maybe_binary_path == null) {
        debug.warn("No binary specified.\n", .{});

        process.exit(1);
    }
    var binary_path = try maybe_binary_path.?;
    // cut off annoying prefix
    if (mem.eql(u8, binary_path[0..2], ".\\")) {
        binary_path = binary_path[2..];
    }

    const cwd = fs.cwd();
    var binary_file = try cwd.openFile(binary_path, fs.File.OpenFlags{});
    defer binary_file.close();

    try binary_file.seekTo(pe_offset_position);
    var pe_tag_offset_bytes: [1]u8 = undefined;
    if ((try binary_file.read(pe_tag_offset_bytes[0..])) != 1) {
        debug.warn("Unable to read PE header start.\n", .{});
        process.exit(0);
    }

    try binary_file.seekTo(pe_tag_offset_bytes[0]);
    var signature_buffer: [6]u8 = undefined;
    const bytes_read = try binary_file.read(signature_buffer[0..]);
    const tag_bytes = signature_buffer[0..4];

    if (bytes_read < 2 or !mem.eql(u8, tag_bytes, "PE\x00\x00")) {
        debug.warn("Weird binary, exiting.\n", .{});
    } else {
        const architecture_bytes = signature_buffer[4..];
        const architecture_string = arch: {
            if (mem.eql(u8, architecture_bytes, "\x64\x86")) {
                break :arch "x64";
            } else if (mem.eql(u8, architecture_bytes, "\x01\x4c")) {
                break :arch "x86";
            } else {
                break :arch "Unknown";
            }
        };
        debug.warn("Architecture: {}\n", .{architecture_string});
    }
}
