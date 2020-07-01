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
    characteristics: Characteristics,
};

pub const Characteristics = struct {
    relocations_stripped: bool,
    executable_image: bool,
    line_numbers_stripped: bool,
    local_symbols_stripped: bool,
    working_set_trim: bool,
    large_address_aware: bool,
    little_endian: bool,
    machine_32bit: bool,
    debugging_info_stripped: bool,
    removable_run_from_swap: bool,
    net_run_from_swap: bool,
    file_system: bool,
    dll: bool,
    uniprocessor_only: bool,
    big_endian: bool,
};

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
    const cv = mem.bytesToValue(u16, characteristics_bytes);

    const relocations_stripped = ((cv & relocations_stripped_position) >> 0) == 1;
    const executable_image = ((cv & executable_image_position) >> 1) == 1;
    const line_numbers_stripped = ((cv & line_numbers_stripped_position) >> 2) == 1;
    const local_symbols_stripped = ((cv & local_symbols_stripped_position) >> 3) == 1;
    const working_set_trim = ((cv & line_numbers_stripped_position) >> 4) == 1;
    const large_address_aware = ((cv & large_address_aware_position) >> 5) == 1;
    const little_endian = ((cv & little_endian_position) >> 7) == 1;
    const machine_32bit = ((cv & machine_32bit_position) >> 8) == 1;
    const debugging_info_stripped = ((cv & debugging_info_stripped_position) >> 9) == 1;
    const removable_run_from_swap = ((cv & removable_run_from_swap_position) >> 10) == 1;
    const net_run_from_swap = ((cv & net_run_from_swap_position) >> 11) == 1;
    const file_system = ((cv & file_system_position) >> 12) == 1;
    const dll = ((cv & dll_position) >> 13) == 1;
    const uniprocessor_only = ((cv & uniprocessor_only_position) >> 14) == 1;
    const big_endian = ((cv & big_endian_position) >> 15) == 1;

    const characteristics = Characteristics{
        .relocations_stripped = relocations_stripped,
        .executable_image = executable_image,
        .line_numbers_stripped = line_numbers_stripped,
        .local_symbols_stripped = local_symbols_stripped,
        .working_set_trim = working_set_trim,
        .large_address_aware = large_address_aware,
        .little_endian = little_endian,
        .machine_32bit = machine_32bit,
        .debugging_info_stripped = debugging_info_stripped,
        .removable_run_from_swap = removable_run_from_swap,
        .net_run_from_swap = net_run_from_swap,
        .file_system = file_system,
        .dll = dll,
        .uniprocessor_only = uniprocessor_only,
        .big_endian = big_endian,
    };

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

const x64_tag = "\x64\x86";
const x86_tag = "\x4c\x01";

const relocations_stripped_position = 0x0001;
const executable_image_position = 0x0002;
const line_numbers_stripped_position = 0x0004;
const local_symbols_stripped_position = 0x0008;
const working_set_trim_position = 0x0010;
const large_address_aware_position = 0x0020;
const little_endian_position = 0x0080;
const machine_32bit_position = 0x0100;
const debugging_info_stripped_position = 0x0200;
const removable_run_from_swap_position = 0x0400;
const net_run_from_swap_position = 0x0800;
const file_system_position = 0x1000;
const dll_position = 0x2000;
const uniprocessor_only_position = 0x4000;
const big_endian_position = 0x8000;
