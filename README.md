# Why?

I wanted/needed a tool to tell me what bitness an executable has. I extended it
a bit but mostly use it for this purpose anyway.

# Usage

## Flags

Pass:

- `-c` for some general characteristics of the file.
- `-se` for the number of sections in the file.
- `-sy` for the number of symbols in the file.

## Example

```
❯ binarch.exe .\zig-cache\bin\binarch.exe -c -sy -se
zig-cache\bin\binarch.exe        
        Machine Type: x64        
        Sections: 7
        Symbols: 0
        Executable:           Yes
        DLL:                  No 
        Large Address Aware:  Yes
```
