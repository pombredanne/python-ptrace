#!/usr/bin/env python
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram
from sys import stderr, argv, exit

def playWithProcess(process):
    process.cont()
    event = process.waitEvent()

def traceProgram(arguments):
    # Copy the environment variables
    env = None

    # Get the full path of the program
    arguments[0] = locateProgram(arguments[0])

    # Create the child process
    return createChild(arguments, False, env)

def allocateMemory(process):
	
	syscall_opcode = "\xCD\x80"
	mmap_syscall_nr = 192
	
	eip = process.getreg("eip")
	old_regs = process.getregs()
	old_instrs = process.readBytes(eip, len(syscall_opcode))
	process.writeBytes(eip, syscall_opcode)
	process.setreg("eax", mmap_syscall_nr)
	
	process.setreg("ebx", 0)
	process.setreg("ecx", 0x2000)
	process.setreg("edx", 0x3)
	process.setreg("esi", 0x22)
	process.setreg("edi", -1)
	process.setreg("ebp", 0)

	process.singleStep()
	print process.waitEvent()

	mem = process.getreg("eax")
	
	process.setregs(old_regs)
	process.setInstrPointer(eip)
	process.writeBytes(eip, old_instrs)

	print hex(mem)
	return mem

def main():
    # User asked to create a new program and trace it
    arguments = argv[2:]
    pid = traceProgram(arguments)
    is_attached = True

    # Create the debugger and attach the process
    dbg = PtraceDebugger()
    process = dbg.addProcess(pid, is_attached)

    process.createBreakpoint(int(argv[1], 16), None)

    mem = allocateMemory(process)

    playWithProcess(process)

    ip = process.getInstrPointer() - 1
    breakpoint = process.findBreakpoint(ip)
    if breakpoint:
        print ("Stopped at %s" % breakpoint)
        breakpoint.desinstall(set_ip=True)

    new_str_addr = mem + 0x100
    arg_addr = process.getreg("esp") + 4
    arg = process.readWord(arg_addr)
    print process.readCString(arg, 10)
    process.writeBytes(new_str_addr, "01234567890")
    process.writeWord(arg_addr, new_str_addr)
    arg = process.readWord(arg_addr)
    print process.readCString(arg, 10)

    playWithProcess(process)
    dbg.quit()

if __name__ == "__main__":
    main()
