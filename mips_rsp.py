#!/usr/bin/python
# Author:
#  Artem Kondratenko (@artkond)

import serial
import time
import logging
from struct import pack, unpack
import sys
import capstone as cs
from termcolor import colored

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

tn = None

reg_map =   {1: 'at', 2: 'v0', 3: 'v1', 4:'a0', 
            5:'a1', 6: 'a2', 7: 'a3', 8: 't0', 
            9: 't1', 10: 't2', 11: 't3', 12: 't4', 
            13: 't5', 14: 't6', 15: 't7', 16: 's0', 
            17: 's1', 18: 's2', 19: 's3', 20: 's4',
            21: 's5', 22: 's6', 23: 's7', 24: 't8', 
            25: 't9', 26: 'k0', 27: 'k1', 28: 
            'gp', 29:'sp', 30: 's8', 31:'ra', 37:'pc'}

reg_map_rev = {}

breakpoints = {}
breakpoints_count = 0

aslr_offset = None

isSerial = True

for k, v in reg_map.iteritems():
    reg_map_rev[v] = k

if len(sys.argv) < 2:
    print 'Specify serial device as a parameter'
    sys.exit(1)

ser = serial.Serial(
    port=sys.argv[1],
    timeout=5
)


def hexdump_gen(byte_string, _len=16, base_addr=0, n=0, sep='-'):
    FMT = '{}  {}  |{}|'
    not_shown = ['  ']
    leader = (base_addr + n) % _len
    next_n = n + _len - leader
    while byte_string[n:]:
        col0 = format(n + base_addr - leader, '08x')
        col1 = not_shown * leader
        col2 = ' ' * leader
        leader = 0
        for i in bytearray(byte_string[n:next_n]):
            col1 += [format(i, '02x')]
            col2 += chr(i) if 31 < i < 127 else '.'
        trailer = _len - len(col1)
        if trailer:
            col1 += not_shown * trailer
            col2 += ' ' * trailer
        col1.insert(_len // 2, sep)
        yield FMT.format(col0, ' '.join(col1), col2)
        n = next_n
        next_n += _len


def isValidDword(hexdword):
    if len(hexdword) != 8:
        return False
    try:
        hexdword.decode('hex')
    except TypeError:
        return False
    return True

def checksum(command):
    csum = 0
    reply = ""
    for x in command:
        csum = csum + ord(x)
    csum = csum % 256
    reply = "$" + command + "#%02x" % csum
    return reply

def decodeRLE(data):
    i=2
    multiplier=0
    reply=""

    while i < len(data):
        if data[i] == "*":
            multiplier = int(data[i+1] + data[i+2],16)
            for j in range (0, multiplier):
                reply = reply + data[i-1]
            i = i + 3
        if data[i] == "#":
            break   
        reply = reply + data[i]
        i = i + 1
    return reply

def print_help():
    print '''Command reference:
c                           - continue program execution
stepi                       - step into
nexti                       - step over
reg                         - print registers
setreg <reg_name> <value>   - set register value
break <addr>                - set break point
info break                  - view breakpoints set
del <break_num>             - delete breakpoint
read <addr> <len>           - read memory
write <addr> <value         - write memory
dump <startaddr> <endaddr>  - dump memory within specified range
gdb kernel                  - send "gdb kernel" command to IOS to launch GDB. Does not work on recent IOS versions.
disas <addr> [aslr]         - disassemble at address. Optional "aslr" parameter to account for code randomization
set_aslr_offset             - set aslr offset for code section

you can also manually send any GDB RSP command
    '''

def CreateGetMemoryReq(address, len):
    address = "m" + address + "," + len
    formatted = checksum(address)
    formatted = formatted + "\n"
    return formatted

def DisplayRegistersMIPS(regbuffer):
    regvals = [''] * 39
    buf = regbuffer
    for k, dword in enumerate([buf[i:i+8] for i in range(0, len(buf), 8)]):
        regvals[k] = dword
    return regvals

def GdbCommand(command):
    global isSerial
    logger.debug('GdbCommand sending: {}'.format(checksum(command))) 
    
    ser.write('{}'.format(checksum(command)))
    if command == 'c':
        return ''
    out = ''
    char =''
    while char != "#":
        char = ser.read(1)     
        out = out + char    
    ser.read(2)            

    logger.debug('Raw output from cisco: {}'.format(out))
    newrle = decodeRLE(out)
    decoded = newrle.decode()
    while decoded[0] == "|" or decoded[0] == "+" or decoded[0] == "$":
        decoded = decoded[1:]
    return decoded    

def OnReadReg():
    regs =  DisplayRegistersMIPS(GdbCommand('g'))
    print 'All registers:'
    for k, reg_name in reg_map.iteritems():
        print "{}: {}".format(reg_name, regs[reg_map_rev[reg_name]])
    print 'Control registers:'
    print "PC: {} SP: {} RA: {}".format(regs[reg_map_rev['pc']],regs[reg_map_rev['sp']], regs[reg_map_rev['ra']])
    return regs

def OnWriteReg(command):
    lex = command.split(' ')
    (_ , reg_name, reg_val) = lex[0:3]
    if reg_name not in reg_map_rev:
        logger.error('Unknown register specified')
        return
    if not isValidDword(reg_val):
        logger.error('Invalid register value supplied')
        return
    logger.debug("Setting register {} with value {}".format(reg_name, reg_val))
    regs =  DisplayRegistersMIPS(GdbCommand('g'))
    regs[reg_map_rev[reg_name]] = reg_val.lower()
    buf = ''.join(regs)
    logger.debug("Writing register buffer: {}".format(buf))
    res = GdbCommand('G{}'.format(buf))
    if 'OK' in res:
        return True
    else:
        return None

def OnReadMem(addr, length):
    if not isValidDword(addr):
        logger.error('Invalid address supplied')
        return None
    if length > 199:
        logger.error('Maximum length of 199 exceeded')
        return None    
    res = GdbCommand('m{},{}'.format(addr.lower(),hex(length)[2:]))
    if res.startswith('E0'):
        return None
    else:
        return res
    
def OnWriteMem(addr, data):
    res = GdbCommand('M{},{}:{}'.format(addr.lower(), len(data)/2, data))
    if 'OK' in res:
        return True
    else:
        return None
    
def hex2int(s):
    return unpack(">I", s.decode('hex'))[0]

def int2hex(num):
    return pack(">I", num & 0xffffffff).encode('hex')

def OnBreak(command):
    global breakpoints
    global breakpoints_count
    lex = command.split(' ')
    
    (_ ,addr) = lex[0:2]
    if not isValidDword(addr):
        logger.error('Invalid address supplied')
        return
    if len(lex) == 3:
        if lex[2] == 'aslr' and aslr_offset != None:
            addr = int2hex(hex2int(addr) + aslr_offset) 
    addr = addr.lower().rstrip()
    if addr in breakpoints:
        logger.info('breakpoint already set')
        return
    opcode_to_save = OnReadMem(addr, 4)
    if opcode_to_save is None:
        logger.error('Can\'t set breakpoint at {}. Read error'.format(addr))
        return
    res = OnWriteMem(addr, '0000000d')
    if res:
        breakpoints_count += 1
        breakpoints[addr] = (breakpoints_count, opcode_to_save)
        logger.info('Breakpoint set at {}'.format(addr))
    else:
        logger.error('Can\'t set breakpoint at {}. Error writing'.format(addr))

def OnDelBreak(command):
    global breakpoints
    global breakpoints_count
    (_, b_num) = command.rstrip().split(' ')
    logger.debug('OnDelBreak')
    item_to_delete = None
    for k, v in breakpoints.iteritems():
        try:
            if v[0] == int(b_num):
                res = OnWriteMem(k, v[1]) 
                if res:
                    item_to_delete = k
                    break
                else:
                    logger.error('Error deleting breakpoint {} at {}'.format(b_num, k))
                    return
        except ValueError:
            logger.error('Invalid breakpoint num supplied')
            return
    if item_to_delete is not None:
        del breakpoints[k]
        logger.info('Deleted breakpoint {}'.format(b_num))

def OnSearchMem(addr, pattern):
    cur_addr = addr.lower()
    buf = ''
    i = 0
    while True:
        i += 1
        mem = GdbCommand('m{},00c7'.format(cur_addr))
        buf += mem
        if i %1000 == 0:
            print  cur_addr
            print hexdump(mem.decode('hex'))
        if pattern in buf[-100:-1]:
            print 'FOUND at {}'.format(cur_addr)
            return
        cur_addr = pack(">I", unpack(">I",cur_addr.decode('hex'))[0] + 0xc7).encode('hex')

def OnListBreak():
    global breakpoints
    global breakpoints_count
    for k, v in breakpoints.iteritems():
        print '{}: {}'.format(v[0], k)

def OnStepInto():
    ser.write("$s#73\r\n")
    ser.read(5)
    OnReadReg()
    OnDisas('disas')

def OnNext():
    regs = OnReadReg()
    pc = unpack('>I', regs[reg_map_rev['pc']].decode('hex'))[0]
    pc_after_branch = pc + 8 
    pc_in_hex = pack('>I', pc_after_branch).encode('hex')
    OnBreak('break {}'.format(pc_in_hex))
    GdbCommand('c')
    OnReadReg()
    OnDelBreak('del {}'.format(breakpoints[pc_in_hex][0])) 

def OnDumpMemory(start, stop):
    buf = ''
    print start, stop
    if not isValidDword(start) or not isValidDword(stop):
        logger.error('Invalid memory range specified')
        return 
    cur_addr = start
    while unpack(">I",cur_addr.decode('hex'))[0] < unpack(">I", stop.decode('hex'))[0]:
        res = GdbCommand('m{},00c7'.format(cur_addr))
        logger.info('Dumping at {} len {}'.format(cur_addr, len(res)))
        cur_addr = pack(">I", unpack(">I",cur_addr.decode('hex'))[0] + 0xc7).encode('hex')
        buf += res
    return buf

def OnSetAslrOffset():
    global aslr_offset
    (_, offset) = command.rstrip().split(' ')
    aslr_offset = hex2int(offset)
    logger.info('ASLR offset set to: 0x{}'.format(offset))

def OnDisas(command):
    lex = command.rstrip().split(' ')

    regs =  DisplayRegistersMIPS(GdbCommand('g'))
    pc = hex2int(regs[reg_map_rev['pc']])
    
    for lexem in lex[1:]:
        if lexem != 'aslr':
            if not isValidDword(lexem):
                logger.error('Invalid address supplied')
                return
            pc = hex2int(lexem) 

    logger.debug('OnDisas PC = {}'.format(pc))
    buf = OnReadMem(int2hex(pc - 20 * 4), 40 * 4)
    md = cs.Cs(cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN)
    
    if len(lex) > 1:
        if lex[1] == 'aslr' and aslr_offset != None:
            pc -= aslr_offset

    for i in md.disasm(buf.decode('hex'), pc - 20 * 4):
        color = 'green' if i.address == pc else 'blue'
        print("0x%x:\t%s\t%s" %(i.address, colored(i.mnemonic, color), colored(i.op_str, color)))
                

while True:
    try:
        command = raw_input('> command: ').rstrip()
        if command == 'exit':
            sys.exit(0)
        elif command == 'help':
            print_help()
        elif command == 'c':
            GdbCommand('c')
        elif command == 'stepi':
            OnStepInto()
        elif command == 'nexti':
            OnNext()
        elif command == 'reg':
            OnReadReg()
        elif command.startswith('setreg'):
            OnWriteReg(command)
        elif command.startswith('break'):
            OnBreak(command)
        elif command.startswith('del'):
            OnDelBreak(command)
        elif command.startswith('info b'):
            OnListBreak()
        elif command.startswith('read'):
            _, start, length = command.split(' ')
            buf = OnReadMem(start, int(length))
            for line in hexdump_gen(buf.decode('hex'), base_addr=hex2int(start), sep=' '):
                print line
        elif command.startswith('write'):
            _, dest, value = command.split(' ')
            value.decode('hex')
            OnWriteMem(dest, value)
        elif command.startswith('search'):
            _, addr, pattern = command.split(' ') 
            OnSearchMem(addr, pattern)
        elif command.startswith('gdb kernel'):
            ser.write('{}\n'.format('gdb kernel'))
        elif command.startswith('dump'):
            _, start, stop = command.split(' ')
            buf = OnDumpMemory(start.lower(), stop.lower())
            if buf is None:
                continue
            else:
                with open('dump_file','wb') as f:
                    f.write(buf)
                logger.info('Wrote memory dump to "dump_file"')
        elif command.startswith('set_aslr_offset'):
            OnSetAslrOffset()
        elif command.startswith('disas'):
            OnDisas(command)
        else:

            ans = raw_input('Command not recognized.\nDo you want to send raw command: {} ? [yes]'.format(checksum(command.rstrip())))
            if ans == '' or ans == 'yes': 
                reply = GdbCommand(command.rstrip())
                print 'Cisco response:', reply.rstrip()
    except (KeyboardInterrupt, serial.serialutil.SerialException, ValueError, TypeError) as e:
        print '\n{}'.format(e)
        print 'Type "exit" to end debugging session'