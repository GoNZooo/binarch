const std = @import("std");
const process = std.process;
const mem = std.mem;
const heap = std.heap;
const fs = std.fs;
const debug = std.debug;
const fmt = std.fmt;

const ArrayList = std.ArrayList;

const pe = @import("./pe.zig");

const Options = struct {
    machine_type: bool,
    sections: bool,
    binaries: ArrayList([]u8),

    pub fn fromArgs(allocator: *mem.Allocator, args: [][]u8) !Options {
        var machine_type = true;
        var sections = false;
        var binaries = ArrayList([]u8).init(allocator);

        for (args) |a| {
            if (mem.eql(u8, a, "-m")) {
                machine_type = true;
            } else if (mem.eql(u8, a, "-s")) {
                sections = true;
            } else {
                try binaries.append(a);
            }
        }

        return Options{ .machine_type = machine_type, .sections = sections, .binaries = binaries };
    }
};

fn outputPEHeader(path: []const u8, header: pe.PEHeader, options: Options) !void {
    const machine_type = switch (header.machine_type) {
        .x64 => "x64",
        .x86 => "x86",
        .unknown => "unknown",
    };
    var machine_type_buffer: [32]u8 = undefined;
    const machine_type_output = if (options.machine_type)
        try fmt.bufPrint(&machine_type_buffer, "\n\tMachine Type: {}", .{machine_type})
    else
        "";

    var sections_buffer: [32]u8 = undefined;
    const sections_output = if (options.sections)
        try fmt.bufPrint(&sections_buffer, "\n\tSections: {}", .{header.sections})
    else
        "";

    debug.warn("{}{}{}\n", .{ path, machine_type_output, sections_output });
}

pub fn main() anyerror!void {
    const args = try process.argsAlloc(heap.page_allocator);
    const options = try Options.fromArgs(heap.page_allocator, args[1..]);

    const cwd = fs.cwd();
    for (options.binaries.items) |path| {
        var binary_path = path;
        // cut off annoying prefix
        if (mem.eql(u8, binary_path[0..2], ".\\")) binary_path = binary_path[2..];

        var file = try cwd.openFile(binary_path, fs.File.OpenFlags{});
        defer file.close();
        const pe_header = pe.getPEHeader(file) catch |e| {
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
        try outputPEHeader(binary_path, pe_header, options);
    }
}
