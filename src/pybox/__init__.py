#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:       $Id$
########################################################################
# Description:
#   Main module of pybox package
#
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

#native python
import logging

#from pybox module
import emodules
import hooking

#native pybox module
import emb

CB_ADDR = emb.dllGetGenericCallbackAddress()

#Global hook manager that keeps track of all registered python callbacks
HOOK_MANAGER = None

MODULES = None


def get_process_id():
    """returns the pid of the process, in which PyBox runs"""
    return emodules.get_main_pid()

def get_process_path():
    """returns the file path of the process, in which PyBox runs"""
    return emodules.get_main_path()
    

def register_hook(module_name, function_name, callback, additional_data = None):
    """register hook in the hook manager.
    @param module_name: name of loaded module containing the function to hook
    @type module_name: string
    @param function_name: name of function to hook
    @type function_name: string
    @param callback: a callback that is executed if this hook is hit
    @type callback: function
    @param additional_data: Some additional data that will be added to execution context
    @type additional_data: arbitrary
    @return: C{True} if everything went alright, C{False} otherwise
    """
    module_name = module_name.upper()
    target_addr = MODULES.get_function_addrs(function_name, module_name)
    if len(target_addr) > 0:
        target_addr = target_addr[0]
        hookname = "%s.%s" % (module_name, function_name)

        return register_hook_by_addr(hookname, target_addr, callback, additional_data)

    return False


def register_hook_by_addr(hookname, address, callback, additional_data = None):
    """register hook in the hook manager based on given address
    (and name for indexing)
    @param hookname: name of the hook (used for identification)
    @type hookname: string
    @param address: address to hook
    @type address: int
    @param callback: a callback that is executed if this hook is hit
    @type callback: function
    @param additional_data: Some additional data that will be added to execution context
    @type additional_data: arbitrary    
    @return: C{True} if everything went alright, C{False} otherwise
    """
    if not HOOK_MANAGER.is_hooked(address):

        hook = hooking.PyFunctionEntryHook(hookname)

        if additional_data:
            hook.set_hook_data(additional_data)
        
        if not hook.create(address, callback):
            return False
    else:
        exist_hooks = HOOK_MANAGER.get_hooks(address)
        if len(exist_hooks) != 1:
            logging.error("Ambiguous hook list existing for address "\
                          "0x%08x" % address)
            return False
        
        hookname = exist_hooks[0].name #hook.name
        
        hook = hooking.PyHookClone(hookname)
        if additional_data:
            hook.set_hook_data(additional_data)

        if not hook.create(exist_hooks[0], callback):
            return False
        
    HOOK_MANAGER.add_hook(hook)
    return True



def register_return_hook(name, exec_ctx, callback, additional_data = None):
    """register a return hook based on the current return address on stack.
    @param name: a identifying name for this hook
    @type name: string
    @param exec_ctx: current execution context. this is need to extract the
                     current return address
    @type exec_ctx: ExecutionContext
    @param callback: a callback function that is executed if this hook is hit
    @type callback: function
    @param additional_data: Some additional data that will be added to execution context
    @type additional_data: arbitrary    
    @return: Expected trampoline size
    """
    ret_hook = hooking.PyReturnAddressHook(name)
    if not ret_hook.create( exec_ctx.retaddr_p,
                            callback,
                            exec_ctx):
        return False

    if additional_data:
        ret_hook.set_hook_data(additional_data)

    HOOK_MANAGER.add_hook(ret_hook)
    

    return True


def generic_callback_handler(origin_addr, ebp_addr):
    """generic python callback handler that is called by native PyBox callback
    handler
    @param origin_addr: origin address, identifies the hook that triggered this
                        callback
    @type origin_addr: int
    @param ebp_addr: current EBP, needed to create execution context object
    @type ebp_addr: int
    @return: Expected trampoline size
    """
    logging.debug("#"*40)
    logging.debug("generic_callback_handler - call for target: " + \
                 hex(origin_addr) + " with EBP: " + hex(ebp_addr))
    
    if HOOK_MANAGER.find_and_execute(origin_addr, ebp_addr+16):
        logging.debug("generic_callback_handler - specific callback function "\
                      "executed")
    else:
        logging.debug("generic_callback_handler - default callback function "\
                      "exectuted")


def cleanup():
    """Tries to remove all hooks installed by PyBox. """
    logging.info("Cleaning up python module")
    HOOK_MANAGER.remove_all_hooks()


def init():
    """Initializes the backend of PyBox. Checks if a native callback
    is set up and creates management objects. """
    global HOOK_MANAGER, MODULES
    logging.debug("pybox.init - Starting script inside of process.")
    logging.debug("pybox.init - DLL CallbackAddr: " + hex(CB_ADDR))
    gen_cb_installed = emb.dllAttachPythonCallback(generic_callback_handler)
    if gen_cb_installed == 0:
        logging.debug("pybox.init - Python Callback attached.")
    else:
        logging.error("pybox.init - Failed: Attach python callback, error "\
                      "code: " + str(gen_cb_installed))
    
    HOOK_MANAGER = hooking.PyHookManager()
    MODULES = emodules.ExecModulesInfo()

    emb.setCleanupFunction(cleanup)    
    
    logging.debug("pybox.init - exiting.")


def terminate(exitcode):
    """Performs a safe termination of PyBox.
    @param exitcode: Defines the exitcode of the Python environment
    @type exitcode: int
    """
    emb.terminate(exitcode)


def set_global_lock(lock_flag):
    """Sets the global lock status. If Global Lock Status is C{True}, no
    hooks are executed. All control is passsed to the hooked function. Thus,
    this will still run.
    @param lock_flag: Flag to tell if global lock is to be set C{True} or not
                      C{False}
    @type lock_flag: boolean
    """
    emb.setGlobalLock(lock_flag)


def set_cleanup_function(cleanup_function):
    """Sets the cleanup function, which is called when PyBox terminates.
    @param cleanup_function: The callback to execute on cleanup
    @type cleanup_function: function
    """
    emb.setCleanupFunction(cleanup_function)
