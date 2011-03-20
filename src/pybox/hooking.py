#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:       $Id: hooking.py 60 2011-03-14 19:51:43Z leder $
########################################################################
#
#  This file is part of PyBox
#
#  PyBox is free software: you can redistribute it and/or modify it
#  under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful, but
#  WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see
#  <http://www.gnu.org/licenses/>.
#
########################################################################

"""
hooking contains the different hook classes, the context objects
(Register and Execution) that are used in the callbacks. For registering
new hooks use the C{register_hook} and C{register_return_hook} function
from within the C{pybox} main module.
"""

#standard python
import binascii
import ctypes
import logging
import struct

#third party modules
import pydasm

#from pybox module
import pybox
import memorymanager



class PyTrampoline(object):
    """Basic Object to create a trampoline to the generic python distributor
    callback. !!Don't use this object directly but use any of
    C{PyFunctionEntryHook} or C{PyReturnAddressHook}!!
    """
    
    def __init__(self, name):
        """Constructor.
        @param name: Generic name for the trampoline - no real use
        @type name: str
        """
        self.name = name

        #initialize
        self.identifier = 0
        self.original_code = ""
        #FIXME: move to non-object function
        self.callback_function = PyTrampoline.default_callback

        self.hook_data = None

        self.execution_context = None
        self.trampoline_addr = 0

        #Begin hook with endless loop. Used for debugging purposes
        self.hook_inf_loop = False
        #Flag wether this is a persistent or a one time hook
        self.persistent = True
        
        self.trampoline = ""

    def __calc_expected_size(self, suffix_len, arg_count):
        """Calculate the expected trampoline size.
        @param suffix_len: Size of the trampoline suffix. Typically the
                           original, saved code of a hook
        @type suffix_len: int
        @param arg_count: Number of arguments that will be pushed on the
                          the stack as additional function arguments for
                          C callback part
        @type arg_count: int
        @return: Expected trampoline size
        """
        result = 0
        if self.hook_inf_loop != False:
            result += 2
        result += 1 + 5 #PUSHAD + PUSH identifier
        result += 5 * arg_count
        result += 5 + 1 #CALL, POPAD
        #result += arg_count + 1 # pop eax
        result += suffix_len
        result += 5     #final JMP

        # FIXME: computation can be more compact, but so everybody understands
        return result

    def create_trampoline(self, identifier, follow_address, suffix_code,
                          additional_args = [], callback_function = None):
        """Creates the actual trampoline and tells if it was successfull. The
        trampoline is built using the following arguments
        @param identifier: Numeric identifier for this trampoline. It is used
                           in the generic callback handler to identify the
                           registered callback function
        @type identifier: int ( 0<= identifier < 2**32)
        @param follow_address: Address to jump to at the end of the trampoline
        @type follow_address: int
        @param suffix_code: Code sequence to append after callback but before
                            final jump. This is typically used for the saved,
                            original code before it is overwritten by a hook
        @type suffix_code: str (filled with opcodes)
        @param additional_args: Additional arguments to be put on the stack
                                before calling the generic callback
        @type additional_args: list of 32-bit int
        @param callback_function: The actual python function that will be 
                                  called when the trampoline is executed                                  
        @return: C{True} if creation was successful. C{False} otherwise

        The actual trampoline will look like this
        #######################################
        Current trampoline layout:
        # Instruction       ASM
        2 JMP self|nop      EB FE | 90 90 (optional)
        1 PUSHAD            60
        5 PUSH identifier   68 ddccbbaa
        5 PUSH arg[0]       68 11223344
        5 PUSH arg[1]       68 11223344
        ...
        5 CALL PyCallback   E8 callback
        1 POPAD             61
        n SuffixCode        ...
        5 JMP follow_addr   E9 99887766
        #######################################
        """

        tramp_size = self.__calc_expected_size(len(suffix_code), \
                                               len(additional_args))
        self.trampoline = ctypes.create_string_buffer( tramp_size )

        if callback_function:
            self.callback_function = callback_function

        if not (0<= identifier <= 0xffffffff):
            raise ValueError, "Identifier must be in [0, 2**32]"

        if identifier != 0:
            self.identifier = identifier
        else:
            self.identifier = ctypes.addressof(self.trampoline)

        trampoline = ""
        
        # begin with infinite loop for debugging?
        if self.hook_inf_loop != False:
            logging.debug("Beginning trampoline with infite loop")
            trampoline += "\xeb\xfe"

        # PUSHAD
        trampoline += "\x60"

        # PUSH additional arguments
        #  (stdcall in reverse order)
        additional_args.reverse()
        for arg in additional_args:
            if not (0<= arg <= 0xffffffff):
                raise ValueError, "Arguments must be in [0, 2**32]"
            trampoline += "\x68"
            trampoline += struct.pack("I", arg)

        # PUSH identifier
        trampoline += "\x68"
        trampoline += struct.pack("I", self.identifier)

        # CALL to generic C callback handler
        trampoline += "\xE8"
        relative_callback = pybox.CB_ADDR - \
                            (ctypes.addressof(self.trampoline) + \
                             len(trampoline) + 4)
        trampoline += struct.pack("I", relative_callback)

        # FIXME: remove - also in calc size
        #   remove all arguments
        #for i in xrange(len(additional_args)+1):
        #    trampoline += "\x58" #POP eax

        # POPAD
        trampoline += "\x61"

        # suffix_code
        relocated_suffix_code = ""
        #suffix code might be zero in case of return hook
        if len(suffix_code) > 4:
            code = suffix_code
            is_first_instruction = True
            while len(relocated_suffix_code) < 5:
                instr = pydasm.get_instruction(code, pydasm.MODE_32)
                if not instr:
                    logging.warn("Cannot hook. Failed to disassemble bytes: "\
                    "\n" + binascii.hexlify(code))
                    return False
                if instr.type == pydasm.INSTRUCTION_TYPE_JMP:
                    if not is_first_instruction:
                        logging.warn("Cannot hook, late JMP detected.")
                        return False
                    if instr.opcode == 0xE9:
                        if instr.op1.immbytes < 4:
                            logging.warn("Cannot hook JMP, too few operand "\
                            "bytes: %x" % instr.opcode)
                            return False
                        else:
                            logging.debug("Found rel JMP instruction, "\
                            "relocating.")
                            relocated_suffix_code += "\xE9"
                            relocated_suffix_code += \
                                        self.relocate_addr(identifier, \
                                        instr.op1.immediate, \
                                        (ctypes.addressof(self.trampoline) + \
                                        len(trampoline))+5)
                            break
                    elif instr.opcode == 0xEB:
                        logging.warn("Cannot hook SHORT JMP")
                        return False
                    else:
                        logging.debug("hooking absolute JMP.")
                        relocated_suffix_code = suffix_code
                        break
                elif instr.type == pydasm.INSTRUCTION_TYPE_JMPC:
                    if not is_first_instruction:
                        logging.warn("Cannot hook, late JMPC detected.")
                        return False
                    if instr.opcode in range(0x80, 0x8F):
                        if instr.op1.immbytes < 4:
                            logging.warn("Cannot hook JMPC, too few operand "\
                            "bytes.")
                            return False
                        else:
                            logging.debug("Found rel JMPC instruction, "\
                            "relocating.")
                            relocated_suffix_code += "\x0F"
                            relocated_suffix_code += chr(instr.opcode)
                            relocated_suffix_code += self.relocate_addr(\
                                        identifier, \
                                        instr.op1.immediate, \
                                        (ctypes.addressof(self.trampoline) + \
                                        len(trampoline)))
                            break
                    elif instr.opcode in range(0x70, 0x7F) or \
                         instr.opcode == 0xE3:
                        logging.warn("Cannot hook SHORT JMPC")
                        return False
                    else:
                        logging.error("should not be reached, opcode: %x" % \
                                      instr.opcode)
                elif instr.type == pydasm.INSTRUCTION_TYPE_CALL:
                    if not is_first_instruction:
                        logging.warn("Cannot hook, late CALL detected.")
                        return False
                    if instr.opcode == 0xE8:
                        if instr.op1.immbytes < 4:
                            logging.warn("Cannot hook CALL, too few operand "\
                            "bytes.")
                            return False
                        else:
                            logging.debug("Found rel CALL instruction, "\
                            "relocating.")
                            relocated_suffix_code += "\xE8"
                            relocated_suffix_code += self.relocate_addr(\
                                        identifier, \
                                        instr.op1.immediate, \
                                        (ctypes.addressof(self.trampoline) + \
                                        len(trampoline)))
                            break
                    else:
                        logging.debug("Found absolute CALL instruction, "\
                        "hooking.")
                        relocated_suffix_code = suffix_code
                        break
                else:
                    relocated_suffix_code += code[:instr.length]
                code = code[instr.length:]
            
        trampoline += relocated_suffix_code

        # final JMP
        trampoline += "\xE9"
        relative_jmp_target = follow_address - \
                              (ctypes.addressof(self.trampoline) + \
                               len(trampoline) + 4)
        trampoline += struct.pack("I", relative_jmp_target)

        if len(trampoline) > tramp_size:
            logging.critical("Trampoline size calculation failed. Please "\
                             "send a bug report to "\
                             "{leder,plohmann}@cs.uni-bonn.de")
            return False

        tempbuf = ctypes.create_string_buffer(trampoline, tramp_size)
        ctypes.memmove(self.trampoline, tempbuf, tramp_size)

        if not memorymanager.set_executable(ctypes.addressof(self.trampoline),
                                            tramp_size):
            logging.error("Cannot set the trampoline to be executable at "\
                          "address 0x%08x"\
                          % ctypes.addressof(self.trampoline))
            return False

        return True

    def create(self):
        """Create the hook. Dummy to be implemented in derived classes"""
        pass

    def remove(self):
        """Removes the hook. Dummy to be implemented in derived classes"""
        pass

    def set_hook_data(self, hook_data):
        """Add some extra data to hook that can be added used with the execution
        context.
        @param additional_data: Some additional data related to hook (will be
                                  added to execution_context)
        @type additional_data: arbitrary
        """
        self.hook_data = hook_data
    
    
    @staticmethod
    def relocate_addr(orig_base, orig_imm, tramp_addr):
        """relocate target addr when backing up relative JMP, JMPC or CALL 
        instruction
        @param orig_base: addr where original instruction was located
        @type orig_base: int (0<= func_entry_addr < 2**32)
        @param orig_imm: immediate parameter as given in original instruction
        @type orig_imm: int (0<= func_entry_addr < 2**32)
        @param tramp_addr: starting address of relocated instruction
        @type tramp_addr: int (0<= func_entry_addr < 2**32)
        @return: relocated addr (packed)
        """
        orig_target = orig_base + orig_imm
        relocated_offset = orig_target - tramp_addr
        return struct.pack("I", relocated_offset)

    @staticmethod   
    def default_callback(execution_context):
        """default callback that is used if no specific callback has been
        defined.
        @param execution_context: current execution context of process
        @type execution_context: object
        """
        logging.info("default callback")



class PyFunctionEntryHook(PyTrampoline):
    """Class that implements hooking on function entry"""

    def create(self, func_entry_addr, callback_function):
        """Creates the hook.
        @param func_entry_addr: The address of the function entry to hook
        @type func_entry_addr: int (0<= func_entry_addr < 2**32)
        @param callback_function: Python callback function
        @type callback_function: Python function with parameter 
                                 (ExecutionContext)
        @return: C{True} on success. C{False} on failure
        """

        if not (0<= func_entry_addr <= 0xffffffff):
            raise ValueError, "Invalid function entry address <> [0, 2**32]"
        
        # read disassembly and make sure we can at least 5 consecutive bytes
        # longest x86 instruction is 15 bytes:
        # add [ds:esi+ecx*2+0x67452301], 0xEFCDAB89 
        code = memorymanager.read_addr(func_entry_addr, 20)
        save_code = ""
        while len(save_code) < 5:
            instr = pydasm.get_instruction(code, pydasm.MODE_32)
            if not instr:
                logging.warn("Cannot hook. Failed to disassemble bytes: \n" + \
                             binascii.hexlify(code))
                return False
            save_code += code[:instr.length]
            code = code[instr.length:]

        # create trampoline
        if not self.create_trampoline(func_entry_addr,
                                      func_entry_addr + len(save_code),
                                      save_code,
                                      [1], #check locking
                                      callback_function):
            logging.warn("Failed to create trampoline")
            return False

        # overwrite the original code (write hook)
        tramp_offset = ctypes.addressof(self.trampoline) - (func_entry_addr + 5)
        hook_code = "\xE9" + struct.pack("I", tramp_offset)
        hook_code += "\x90"*(len(save_code)-5)
        #hook_code = "\xeb\xfe" + hook_code

        if memorymanager.write_mem(func_entry_addr, hook_code):
            logging.debug("Successfully hooked target address %08x -> %08x" %\
                          (func_entry_addr, ctypes.addressof(self.trampoline)))
        else:
            logging.error("Failed to create hook at address %08x" % \
                          func_entry_addr)
            return False
        
        return True


    def remove(self):
        """Removes the hook"""
        if memorymanager.write_mem(self.identifier, self.original_code):
            logging.debug("Successfully removed hook at address %08x" % \
                          self.identifier)
        else:
            logging.error("Failed to remove hook at address %08x" % \
                          self.identifier)
            return False

        return True
        


class PyReturnAddressHook(PyTrampoline):
    """Class that implements hooking on return addresses"""

    def __init__(self, name):
        PyTrampoline.__init__(self, name)

        self.original_retaddr = 0
        self.persistent = False
        #self.hook_inf_loop = True
    
    def create(self, ret_addr_p, callback_function, execution_context):
        """Creates the hook.
        @param ret_addr_p: The address where the return address is found
        @type ret_addr_p: int (0<= ret_addr_p < 2**32)
        @param callback_function: Python callback function
        @type callback_function: Python function with parameter 
                                 (ExecutionContext)
        @param execution_context: execution context in which the return hook
                                  should be set
        @type execution_context: ExecutionContext
        @return: C{True} on success. C{False} on failure
        """
        if not (0<= ret_addr_p <= 0xffffffff):
            raise ValueError, "Invalid return address pointer <> [0, 2**32]"

        # store information
        self.execution_context = execution_context
        self.original_retaddr = execution_context.get_return_addr()

        # create trampoline
        if not self.create_trampoline(0,
                                      self.original_retaddr,
                                      "",
                                      [1], #don't check locking
                                      callback_function):
            logging.warn("Failed to create trampoline")
            return False

        # change return address
        execution_context.set_return_addr(ctypes.addressof(self.trampoline))

        return True


class PyHookClone(PyFunctionEntryHook):
    """Clone of an existing hook. Used if the memory location is already
    modified at redirects to central, generic callback"""


    def create(self, reference_hook, callback_function):
        """Constructor
        @param name: Generic name for the trampoline - no real use
        @type name: str
        @param reference_hook: Existing hook that has already patched the 
                               binary
        @type reference_hook: PyTrampoline
        """
        
        self.identifier = reference_hook.identifier
        self.original_code = reference_hook.original_code
        
        self.trampoline = reference_hook.trampoline
        self.trampoline_addr = reference_hook.trampoline_addr
        
        self.hook_inf_loop = reference_hook.hook_inf_loop
        self.persistent = reference_hook.persistent

        self.execution_context = reference_hook.execution_context
        self.callback_function = callback_function

        return True
        

class RegisterContext(object):
    """Access to registers stored on stack based on attribute names"""

    offsets = {
        "EDI": 0,
        "ESI": 4,
        "EBP": 8,
        "ESP": 0xc,
        "EDX": 0x10,
        "ECX": 0x14,
        "EBX": 0x18,
        "EAX": 0x1C
        }

    def __init__(self, register_base_addr):
        """initialize
        @param register_base_addr: base address in memory holding registers
                                   stored with pushad
        @param register_base_addr: int
        """
        self.base_addr = register_base_addr

    def __setattr__(self, name, value):
        """Set register value
        @param name: Register name (can be upper or lower)
        @type name: str
        @param value: The numeric value to put in the register
        @type value: int ( 0 <= value < 2**32)
        """
        
        reg_name = name.upper()
        if not RegisterContext.offsets.has_key(reg_name):
            return object.__setattr__(self, name, value)

        if not (0<= value <= 0xffffffff):
            raise ValueError, "Register value must be inbetween 0 and "\
                              "0xFFFFFFFF"

        offset = RegisterContext.offsets[reg_name]
        reg_val = struct.pack("I", value)
        memorymanager.write_mem(self.base_addr + offset, reg_val)

    def __getattribute__(self, name):
        reg_name = name.upper()
        if not RegisterContext.offsets.has_key(reg_name):
            return object.__getattribute__(self, name)

        offset = RegisterContext.offsets[reg_name]
        data = memorymanager.read_addr(self.base_addr + offset, 4)
        if len(data) != 4:
            logging.warn("Cannot get register contents. Memory addres 0x%08x "\
                         "not readable" %\
                         self.base_addr + offset)
            return None

        return struct.unpack("I", data)[0]



class ExecutionContext(object):

    def __init__(self, frame_addr, identifier, hook = None):
        """Initialize
        @param frame_addr: Base address of stack frame
        @type frame_addr: int
        @param identifier: hook identifier (name)
        @type identifier: str
        @param hook: the hook belonging to this context
        @type hook: Sibling of PyTrampoline
        """
        self.regs = RegisterContext(frame_addr)
        self.retaddr_p = frame_addr + 32
        self.stack_params = frame_addr + 36
        self.identifier = identifier
        self.hook = hook

    def get_return_addr(self):
        """@return: return address (int)"""
        return memorymanager.read_dword_from_addr(self.retaddr_p)

    def set_return_addr(self, new_ret_addr):
        """Changes the return address
        @param new_ret_addr: New return address
        @type new_ret_addr: int (0<= new_ret_addr <= 0xFFFFFFFF)
        """
        if not (0<= new_ret_addr <= 0xffffffff):
            raise ValueError, "Return address must be inbetween 0 and "\
                              "0xFFFFFFFF"
        rval = struct.pack("I", new_ret_addr)
        return memorymanager.write_mem(self.retaddr_p, rval)

    def get_arg(self, arg_index):
        """Assumes that each parameter on the stack is 4-bytes in size.
        Returns the n-th of those parameters.
        @param arg_index: Index of function parameters
        @type arg_index: int
        @return: (unsigned) int containing the value of the parameter
        """
        return memorymanager.read_dword_from_addr(self.stack_params +\
                                               (arg_index << 2))

    def set_arg(self, arg_index, value):
        """Assumes that each parameter on the stack is 4-bytes in size.
        Sets the n-th of those parameters.
        @param arg_index: Index of function parameters
        @type arg_index: int
        @param value: The numeric value to put in the register
        @type value: int ( 0 <= value < 2**32)
        """
        if not (0<= value <= 0xffffffff):
            raise ValueError, "Parameter must be inbetween 0 and 0xFFFFFFFF"
        rval = struct.pack("I", value)
        
        return memorymanager.write_mem(self.stack_params + (arg_index <<2),
                                       rval)

    def get_stack_args(self, formatting):
        """Assumes that each argument on the stack is 4-bytes in size.
        Returns parsed versions of those arguments.
        @param format: Format in which each of those arguments is to be parsed
                     "a" : Pointer to ANSI string
                     "u" : Pointer to Unicode string
                     "d" : return numeric (unsigned) value
                     "p" : return numeric (unsigned) value that is pointed to
        @type foramt: str
        @return: list of parsed arguments (each as defined type)
        """
        
        num_args = len(formatting)

        retval = []
        for i in xrange(num_args):
            arg = self.get_arg(i)

            if formatting[i] == "a":
                retval.append("%s" % memorymanager.read_ascii_from_addr(arg))
            elif formatting[i] == "u":
                retval.append("%s" % memorymanager.read_unicode_from_addr(arg))
            elif formatting[i] == "d":
                retval.append(arg)
            elif formatting[i] == "p":
                retval.append(memorymanager.read_dword_from_pointer(arg))
        return retval


    def renew_register_context(self, new_frame_addr):
        """Re-initializes the registers. This is necessary e.g. for return
        hooks. For those the original stack frame stays the same, but registers
        are different upon function return.
        @param new_frame_addr: New start of context frame (location of pushad)
        @type new_frame_addr: int
        """
        self.regs = RegisterContext(new_frame_addr)

    
        
    
class PyHookManager(object):
    
    def __init__(self):
        self.hooks = {}
        self.active_addrs = []
        
    def __del__(self):
        pass


    def get_hook_count(self):
        """return number of already installed hooks
        """
        return len(self.hooks)
    
    def add_hook(self, hook):
        """Add hook to global manager object
        @param hook: Hook to add to manager
        @type hook: Sibling of PyTrampoline
        """
        hook_addr = hook.identifier
        
        if self.hooks.has_key(hook_addr):
            self.hooks[hook_addr].append(hook)
            logging.debug("Adding another hook for addr 0x%08x (name: %s)" % \
                          (hook_addr,
                           hook.name))
        else:
            self.hooks[hook_addr] = [hook]

       
    def remove_hook(self, hook):
        """Remove hook based on its identifier address
        @param hook: Hook
        @type hook: PyTrampoline
        """
        addr = hook.identifier

        if not self.is_hooked(addr):
            logging.error("Cannot remove hook at address 0x%08x: Not "\
                          "registered" % addr)
        else:
            if (len(self.hooks[addr]) != 1) or (not addr in self.active_addrs):
                logging.debug("Removing hook at address 0x%08x" % addr)
                self.hooks[addr].remove(hook)
                
                if len(self.hooks[addr]) == 0:
                    hook.remove() #only remove if this is last of its kind
                    self.hooks.pop(addr)
            else:
                logging.warn("Cannot remove hook %s at address 0x%08x - it "\
                "is active!" % (hook.name, addr))


    def remove_all_hooks(self):
        """Removes all registered hooks"""
        if len(self.active_addrs) > 0:
            logging.error("Cannot remove all hooks from within active hook")
        else:
            for hooklist in self.hooks.values():
                for hook in hooklist:
                    self.remove_hook(hook)


    def get_hooks(self, hook_addr=None, callback=None):
        """Get the hook object for the given hook_address (optional)
        and callback (optional)
        @param hook_addr: The address hooked
        @type hook_addr: int or C{None} if not to be used
        @param callback: The callback of the hook
        @type callback: Python function or C{None} if not to be used
        @return: C{None} if no such hook has been found, list of hooks that
                 match
        """

        result = []
        
        if (hook_addr == None) and (callback == None):
            return None

        search_list = self.hooks.values()
        
        if hook_addr:
            if not self.hooks.has_key(hook_addr):
                return None            
            search_list = [self.hooks[hook_addr]]

        for hook_list in search_list:
            if callback:
                hlist = [h for h in hook_list \
                         if h.callback_function == callback]
                result += hlist
            else:
                result += hook_list

        return result
            

    def is_hooked(self, addr):
        """Tells whether the given address is already hooked. This information
        is obtained from the hookmanager's database.
        @param addr: Hook identifier
        @type addr: int
        """
        return self.hooks.has_key(addr)        
            
    def find_and_execute(self, origin_addr, frame_addr):
        if self.is_hooked(origin_addr):
            found_hooks = self.hooks[origin_addr]

            for fhook in found_hooks:

                if fhook.execution_context == None:
                    ectx = ExecutionContext(frame_addr, fhook.identifier, fhook)
                else:
                    ectx = fhook.execution_context
                    ectx.renew_register_context(frame_addr)
                    ectx.hook=fhook

                self.active_addrs.append(origin_addr)
                fhook.callback_function(ectx)
                self.active_addrs.remove(origin_addr)

                if not fhook.persistent:
                    self.remove_hook(fhook)

            return 1
        
        else:
            logging.warn("Hook for address 0x%08x not registered. Cannot "\
            "call" % origin_addr)
            ectx = ExecutionContext(frame_addr, origin_addr)
            PyTrampoline.default_callback(ectx)
        return 0        
