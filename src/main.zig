const std = @import("std");
const process = std.process;
const mem = std.mem;
const heap = std.heap;
const fs = std.fs;
const debug = std.debug;

pub fn main() anyerror!void {
    var arg_iterator = process.ArgIterator.init();
    _ = arg_iterator.next(heap.page_allocator);
    const maybe_binary_path = arg_iterator.next(heap.page_allocator);
    if (maybe_binary_path == null) {
        debug.warn("No binary specified.\n", .{});

        process.exit(1);
    }
    const binary_path = try maybe_binary_path.?;
    const cwd = fs.cwd();
    var binary_file = try cwd.openFile(binary_path, fs.File.OpenFlags{});
    try binary_file.seekBy(0x78);
    var i: u32 = 0;
    var signature_buffer: [6]u8 = undefined;
    signature_buffer[5] = 0;
    const bytes_read = try binary_file.read(signature_buffer[0..]);
    const tag_bytes = signature_buffer[0..4];
    if (bytes_read < 2 or !mem.eql(u8, tag_bytes, "PE\x00\x00")) {
        debug.warn("Weird binary, exiting.\n", .{});
    } else {
        const architecture_bytes = signature_buffer[4..];
        debug.warn("Architecture: ", .{});
        if (mem.eql(u8, architecture_bytes, "\x64\x86")) {
            debug.warn("x64\n", .{});
        } else if (mem.eql(u8, architecture_bytes, "\x01\x4c")) {
            debug.warn("x86\n", .{});
        } else {
            debug.warn("Unknown\n", .{});
        }
    }
}
