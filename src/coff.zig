const std = @import("std");
const debug = std.debug;
const mem = std.mem;
const fmt = std.fmt;
const testing = std.testing;
const heap = std.heap;
const fs = std.fs;

const pe = @import("./pe.zig");

pub const MachineType = enum {
    x86,
    x64,
    unknown,
};

pub const COFFHeader = struct {
    machine_type: MachineType,
    // can have maximum 96 sections in a PE file
    sections: u16,
    created: u32,
    symbol_table_offset: u32,
    symbols: u32,
    optional_header_size: u16,
    // @TODO: add deconstruction of this flags value
    characteristics: u16,
};

const x64_tag = "\x64\x86";
const x86_tag = "\x4c\x01";

pub fn getCOFFHeader(file: fs.File) !COFFHeader {
    const pe_tag_offset = try pe.getPESignatureLocation(file);
    try file.seekTo(pe_tag_offset);

    var pe_buffer: [24]u8 = undefined;
    const bytes_read = try file.read(pe_buffer[0..]);
    const tag_bytes = pe_buffer[0..4];

    if (bytes_read < 4 or !mem.eql(u8, tag_bytes, "PE\x00\x00")) {
        return error.NoPESignatureAtHeader;
    } else {
        return try readCOFFHeader(file, pe_buffer[0..]);
    }
}

pub fn readCOFFHeader(file: fs.File, pe_buffer: []u8) !COFFHeader {
    const architecture_bytes = pe_buffer[4..6];
    var machine_type: MachineType = undefined;
    if (mem.eql(u8, architecture_bytes, x64_tag)) {
        machine_type = MachineType.x64;
    } else if (mem.eql(u8, architecture_bytes, x86_tag)) {
        machine_type = MachineType.x86;
    } else {
        machine_type = MachineType.unknown;
    }

    const sections_bytes = pe_buffer[6..8];
    const sections = mem.bytesToValue(u16, sections_bytes);

    const created_bytes = pe_buffer[8..12];
    const created = mem.bytesToValue(u32, created_bytes);

    const symbol_table_offset_bytes = pe_buffer[12..16];
    const symbol_table_offset = mem.bytesToValue(u32, symbol_table_offset_bytes);

    const symbols_bytes = pe_buffer[16..20];
    const symbols = mem.bytesToValue(u32, symbols_bytes);

    const optional_header_size_bytes = pe_buffer[20..22];
    const optional_header_size = mem.bytesToValue(u16, optional_header_size_bytes);

    const characteristics_bytes = pe_buffer[22..24];
    const characteristics = mem.bytesToValue(u16, characteristics_bytes);

    return COFFHeader{
        .machine_type = machine_type,
        .sections = sections,
        .created = created,
        .symbol_table_offset = symbol_table_offset,
        .symbols = symbols,
        .optional_header_size = optional_header_size,
        .characteristics = characteristics,
    };
}
