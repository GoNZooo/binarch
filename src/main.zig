const std = @import("std");
const process = std.process;
const mem = std.mem;
const heap = std.heap;
const fs = std.fs;
const debug = std.debug;
const fmt = std.fmt;

const pe = @import("./pe.zig");

pub fn main() anyerror!void {
    var arg_iterator = process.ArgIterator.init();
    _ = arg_iterator.skip();

    const cwd = fs.cwd();
    while (arg_iterator.next(heap.page_allocator)) |arg| {
        var binary_path = try arg;
        // cut off annoying prefix
        if (mem.eql(u8, binary_path[0..2], ".\\")) binary_path = binary_path[2..];

        const machine_type = pe.getMachineTypeForPath(cwd, binary_path) catch |e| {
            switch (e) {
                error.NoPESignatureAtHeader => {
                    debug.warn("'{}' does not seem to be a PE file.\n", .{binary_path});
                },
                error.FileTooSmall => {
                    debug.warn(
                        "'{}' is possibly an incomplete/too small PE file.\n",
                        .{binary_path},
                    );
                },
                else => {
                    debug.warn("'{}' had IO error of some sort: {}.\n", .{ binary_path, e });
                },
            }
            continue;
        };
        const s = switch (machine_type) {
            .x64 => "x64",
            .x86 => "x86",
            .unknown => "unknown",
        };
        debug.warn("{}: {}\n", .{ binary_path, s });
    }
}
