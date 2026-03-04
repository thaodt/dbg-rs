# dbg-regs-x64

`dbg-regs-x64` maps x86-64 register names/aliases to Linux `user_regs_struct` fields and enforces correct alias semantics.

## Where register names come from

Names like `rip`, `rflags`, `rax`, `eax`, `ah` come from x86-64 ISA documentation and Linux ptrace ABI:

- AMD64 architecture manuals: general-purpose register model (`RAX..R15`), instruction pointer (`RIP`), flags register (`RFLAGS`)
- Intel SDM (equivalent register semantics)
- Linux `struct user_regs_struct` (`<sys/user.h>`) exposed through `PTRACE_GETREGS` / `PTRACE_SETREGS`

So `rip` and `rflags` are not arbitrary project choices; they are canonical architecture registers surfaced by Linux.

## Why `RegisterSpec` has these fields

`RegisterSpec` is the minimum data needed to implement alias read/write correctly:

- `name`: canonical alias string to return (`eax`, `ah`, ...)
- `base`: which full 64-bit register stores the bits (`Rax`, `Rip`, `Rflags`, ...)
- `bits`: alias width (`8/16/32/64`)
- `lsb`: starting bit offset inside `base` (`ah` starts at bit 8)
- `zero_extend_64`: whether x86-64 requires full-register zero-extension on write (true for 32-bit aliases like `eax`)

## Alias semantics implemented

- Writing `eax` sets lower 32 bits of `rax` and clears upper 32 bits
- Writing `ah` updates only bits `8..15` of `rax`
- Reads return masked slices according to alias width/offset

Example (`RAX` family):

```text
RAX (64): [63.............................0]
EAX (32): [31.............0]  write => zero-extend to 64
AX  (16): [15....0]
AH   (8): [15..8]
AL   (8): [7...0]
```

## Public API

- `read_register(&user_regs_struct, name)`
- `write_register(&mut user_regs_struct, name, value)`
- `read_all_gpr(&user_regs_struct)`
