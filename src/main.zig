const std = @import("std");
const process = std.process;
const mem = std.mem;
const heap = std.heap;
const fs = std.fs;
const debug = std.debug;
const fmt = std.fmt;

const coff = @import("./coff.zig");

const ArrayList = std.ArrayList;

const Options = struct {
    machine_type: bool,
    sections: bool,
    symbols: bool,
    characteristics: bool,
    binaries: ArrayList([]u8),

    pub fn fromArgs(allocator: *mem.Allocator, args: [][]u8) !Options {
        var machine_type = true;
        var sections = false;
        var symbols = false;
        var characteristics = false;
        var binaries = ArrayList([]u8).init(allocator);

        for (args) |a| {
            if (mem.eql(u8, a, "-m")) {
                machine_type = true;
            } else if (mem.eql(u8, a, "-se")) {
                sections = true;
            } else if (mem.eql(u8, a, "-sy")) {
                symbols = true;
            } else if (mem.eql(u8, a, "-c")) {
                characteristics = true;
            } else {
                try binaries.append(a);
            }
        }

        return Options{
            .machine_type = machine_type,
            .sections = sections,
            .binaries = binaries,
            .symbols = symbols,
            .characteristics = characteristics,
        };
    }
};

fn outputCOFFHeader(path: []const u8, header: coff.COFFHeader, options: Options) !void {
    const machine_type = switch (header.machine_type) {
        .x64 => "x64",
        .x86 => "x86",
        .unknown => "unknown",
    };
    var machine_type_buffer: [32]u8 = undefined;
    const machine_type_output = if (options.machine_type)
        try fmt.bufPrint(&machine_type_buffer, "\tMachine Type: {}\n", .{machine_type})
    else
        "";

    var sections_buffer: [32]u8 = undefined;
    const sections_output = if (options.sections)
        try fmt.bufPrint(&sections_buffer, "\tSections: {}\n", .{header.sections})
    else
        "";

    var symbols_buffer: [32]u8 = undefined;
    const symbols_output = if (options.symbols)
        try fmt.bufPrint(&symbols_buffer, "\tSymbols: {}\n", .{header.symbols})
    else
        "";

    var characteristics_buffer: [128]u8 = undefined;
    const characteristics_output = if (options.characteristics)
        try header.characteristics.bufPrint(characteristics_buffer[0..], "\t")
    else
        "";

    debug.warn(
        "{}\n{}{}{}{}",
        .{ path, machine_type_output, sections_output, symbols_output, characteristics_output },
    );
}

pub fn main() anyerror!void {
    const arguments = try process.argsAlloc(heap.page_allocator);
    const options = try Options.fromArgs(heap.page_allocator, arguments[1..]);

    const cwd = fs.cwd();
    for (options.binaries.items) |path| {
        var binary_path = path;
        // cut off annoying prefix
        if (mem.eql(u8, binary_path[0..2], ".\\")) binary_path = binary_path[2..];

        var file = try cwd.openFile(binary_path, fs.File.OpenFlags{});
        var buffer: [1024]u8 = undefined;
        const read_bytes = try file.read(buffer[0..]);
        defer file.close();
        const coff_header = coff.getCOFFHeader(buffer[0..]) catch |e| {
            switch (e) {
                error.NoPESignatureAtHeader => {
                    debug.print("'{}' does not seem to be a PE file.\n", .{binary_path});
                },
                else => {
                    debug.print("'{}' had IO error of some sort: {}.\n", .{ binary_path, e });
                },
            }
            continue;
        };
        try outputCOFFHeader(binary_path, coff_header, options);
    }
}
