#!/usr/bin/env python
from ptrace.debugger.debugger import PtraceDebugger
from ptrace.debugger.child import createChild
from ptrace.tools import locateProgram
from ptrace.debugger.process import NewProcessEvent
from sys import stderr, argv, exit

from ptrace.binding import func as ptrace_bindings

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

def createCheckpoint(process):

    syscall_opcode = "\xCD\x80"
    fork_syscall_nr = 2

    eip = process.getreg("eip")
    old_eax = process.getreg("eax")
    old_instrs = process.readBytes(eip, len(syscall_opcode))
    process.writeBytes(eip, syscall_opcode)
    process.setreg("eax", fork_syscall_nr)

    child = None

    process.singleStep()
    ev = process.waitEvent()

    child = ev.process

    process.setreg("eax", old_eax)
    process.setInstrPointer(eip)
    process.writeBytes(eip, old_instrs)

    child.setreg("eax", old_eax)
    child.setInstrPointer(eip)
    child.writeBytes(eip, old_instrs)

    return child
	
class Fuzz(object):

	def try_arg(self, str_argument):
	
		print "Trying argument %s" % str_argument
	
		process = self.test_process
		new_str_addr = self.mem + 0x100
		arg_addr = process.getreg("esp") + 4
		arg = process.readWord(arg_addr)
		process.writeBytes(new_str_addr, str_argument)
		process.writeWord(arg_addr, new_str_addr)
		arg = process.readWord(arg_addr)
		playWithProcess(process)
	
	
	def fuzz(self, arguments, address):
		self.arguments = arguments
   		self.address = address
		self.mem = None
		self.pid = traceProgram(self.arguments)
		self.is_attached = True
	
		self.dbg = PtraceDebugger()
		self.process = self.dbg.addProcess(self.pid, self.is_attached)
	
		self.process.createBreakpoint(self.address, None)
		self.process.setoptions(ptrace_bindings.PTRACE_O_TRACEFORK)
		
		self.mem = allocateMemory(self.process)
		
		playWithProcess(self.process)
		
		ip = self.process.getInstrPointer() - 1
		breakpoint = self.process.findBreakpoint(ip)
		if breakpoint:
		    print ("Stopped at %s" % breakpoint)
		    breakpoint.desinstall(set_ip=True)
		
		for length in range(0, 20):
			self.test_process = createCheckpoint(self.process)
			self.try_arg("a" * length)
			#self.test_process.terminate(True)
		
		self.dbg.quit()

if __name__ == "__main__":
    Fuzz().fuzz(argv[2:], int(argv[1], 16))
