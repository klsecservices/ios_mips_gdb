
Cisco IOS MIPS GDB remote serial protocol implementation
===================

A hacky implementation of GDB RSP to aid exploit development for MIPS based Cisco routers

Command reference
-------------

```
Command reference:
c                           - continue program execution
stepi                       - step into
nexti                       - step over
reg                         - print registers
setreg <reg_name> <value>   - set register value
break <addr>                - set breakpoint
info break                  - view breakpoints set
del <break_num>             - delete breakpoint
read <addr> <len>           - read memory
write <addr> <value         - write memory
dump <startaddr> <endaddr>  - dump memory within specified range
gdb kernel                  - send "gdb kernel" command to IOS to launch GDB. Does not work on recent IOS versions.
disas <addr> [aslr]         - disassemble at address. Optional "aslr" parameter to account for code randomization
set_aslr_offset             - set aslr offset for code section
```

you can also send any GDB RSP command manually

Usage example
-------------
- Launch GDB on the device

```
$ sudo picocom -b 9600  /dev/ttyS0
picocom v2.2
Type [C-a] [C-h] to see available commands

Terminal ready

cisco.local>en
Password: 
cisco.local#gdb kernel
||||

```

- Connect the debugger

```
$ python mips_rsp.py /dev/ttyS0
> command: reg
All registers:
...
Control registers:
PC: 4008f3e0 SP: 47c354d8 RA: 403a026c
> command: disas
...
0x4008f3c4: move    $v0, $zero
0x4008f3c8: lui $t0, 0x45fc
0x4008f3cc: lw  $t0, 0x7ea8($t0)
0x4008f3d0: nop 
0x4008f3d4: ori $t0, $t0, 0x100
0x4008f3d8: mtc0    $t0, $t5, 0
0x4008f3dc: nop 
0x4008f3e0: nop 
0x4008f3e4: j   0x4008f3f0
0x4008f3e8: addiu   $v0, $zero, 1
0x4008f3ec: move    $v0, $zero
0x4008f3f0: lw  $ra, 0x10($sp)
...
> command:     

```

Dependencies
------

Capstone - www.capstone-engine.org

Credits
------

Based on https://github.com/nccgroup/IODIDE

Author
------

Artem Kondratenko https://twitter.com/artkond