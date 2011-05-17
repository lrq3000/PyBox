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
#   tracking component for the start of a new process or remote thread
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

""" This plugin monitors a process regarding initialization of new remote 
    processes and threads. The following ways of starting remote execution 
    covered so far are:
    * 'system()' [-> kernel32.dll.CreateProcess]
    * '_exec()' [-> kernel32.dll.CreateProcess]
    * '_spawn()' [-> kernel32.dll.CreateProcess]
    * 'ShellExecute()' [via Shell32.dll]
    * 'ShellExecuteEx()' [via Shell32.dll]
    * 'WinExec()' [kernel32.dll] 
    * 'CreateProcess()' [kernel32.dll]
    * 'CreateProcessAsUser()' [kernel32.dll]
    * 'CreateProcessWithLogonW()' [kernel32.dll]
    * 'CreateRemoteThread()' [kernel32.dll]
    
    Further ways to consider:
    * 'CreateProcessWithTokenW()' [VISTA kernel32.dll]

    Hooking the following API function covers all the others and returns the
    PID of the process.
    
    * CreateProcessInternalW() [undocumented API call]
    
"""

import logging

import emb
import injector
import pybox
from pybox import memorymanager
import time




def init(): 
    """ initializes this module and registers hooks for API functions that
        can lead to the creation of new processes and threads
    """
    logging.info("remote execution tracking active.")
    if not pybox.register_hook("kernel32.dll",
                     "CreateProcessInternalW",
                     cb_create_process_internal_w):
        logging.error("Failed to register hook for CreateProcessInternalW")
        
    if not pybox.register_hook("kernel32.dll",
                     "CreateRemoteThread",
                     cb_create_r_thread):
        logging.error("Failed to register hook for CreateRemoteThread") 

    if not pybox.register_hook("kernel32.dll",
                     "ResumeThread",
                     cb_resume_thread):
        logging.error("Failed to register hook for CreateRemoteThread") 


    return
                
                     
def cb_create_process_internal_w(exec_ctx):
    """Callback for CreateProcessInternalW"""
    stack_args = exec_ctx.get_stack_args("duuddddduddd")
    logging.info("kernel32.dll.CreateProcessInternalW(0x%08x, %s, %s, " \
                 "0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, %s, 0x%08x, " \
                 "0x%08x, 0x%08x)",
                 stack_args[0], 
                 stack_args[1],
                 stack_args[2], # LPTSTR_CMD_LINE
                 stack_args[3],
                 stack_args[4],
                 stack_args[5],
                 stack_args[6], 
                 stack_args[7],
                 stack_args[8],
                 stack_args[9],
                 stack_args[10], # LP_PROCESS_INFORMATION
                 stack_args[11])
    
    child_proc_info = stack_args[10]

    if not pybox.register_return_hook("CreateProcessInternalW_return", \
                                      exec_ctx, \
                                      cb_create_process_internal_w_rtn,
                                      child_proc_info):
        logging.error("Cannot install return hook for " \
                      "CreateProcessInternalW_return")
    
    return

def cb_create_process_internal_w_rtn(exec_ctx):
    """Return callback for CreateProcessInternalW"""
    logging.debug("CreateProcessInternalW returned 0x%08x", exec_ctx.regs.EAX)

    child_proc_info = exec_ctx.hook.hook_data
    child_pid = memorymanager.read_dword_from_addr(child_proc_info + 8)
    
    logging.debug("PID of spawned process: 0x%08x", child_pid)
    
    logging.debug("starting inject")
    if not injector.inject_module_into_process(emb.dllGetFilename(), child_pid):
        logging.info("Error injecting %s into process %i", \
                     emb.dllGetFilename(), child_pid)
    else:
        logging.debug("inject SUCCESSFUL")
    
    return

def cb_create_r_thread(exec_ctx):
    """Callback for CreateRemoteThread"""
    stack_args = exec_ctx.get_stack_args("ddddddd")
    logging.info("kernel32.dll.CreateRemoteThread(0x%08x, %d, %d, 0x%08x, " \
                 "%d, %d, 0x%08x)",
                 stack_args[0], 
                 stack_args[1],
                 stack_args[2],
                 stack_args[3],
                 stack_args[4],
                 stack_args[5],
                 stack_args[6])
    
    r_threadid_addr = stack_args[6]
    process_handle = stack_args[0]
    
    if process_handle != 0xFFFFFFFF:
        logging.info("PROCESS_HANDLE: 0x%08x" % process_handle)
        pid = emb.dllGetProcessId(process_handle)
        logging.debug("PID of target host process: 0x%08x" % pid)

        hookdata = (pid, r_threadid_addr)
        
        if not pybox.register_return_hook("CreateRemoteThread_return", \
                                          exec_ctx, \
                                          cb_create_r_thread_rtn,
                                          hookdata):
            logging.error("Cannot install return hook for CreateRemoteThread")
    else: 
        logging.info("CreateRemoteThread called on self")

    return

def cb_create_r_thread_rtn(exec_ctx):
    """Return callback for CreateRemoteThread"""
    logging.info("CreateRemoteThread returned 0x%08x", exec_ctx.regs.EAX)
    
    # TODO experimental

    (child_pid, r_threadid_addr) = exec_ctx.hook.hook_data
    
    logging.debug("pointer to TID: 0x%08x" % (r_threadid_addr))
    remote_tid = memorymanager.read_dword_from_addr(r_threadid_addr)
    logging.debug("TID of spawned thread: 0x%08x" % (remote_tid))

    logging.debug("starting inject")
    if not injector.inject_module_into_process(emb.dllGetFilename(), child_pid):
        logging.error("Error injecting %s into process %i" % \
                     (emb.dllGetFilename(), child_pid))
    else:
        logging.debug("inject SUCCESSFUL")

    # injector.inject_module_into_process(dll_path, child_pid)
    
    return


def cb_resume_thread(exec_ctx):
    """ResumeThread"""
    #wait for some seconds to allow injection to come up
    logging.info("ResumeThread")
    time.sleep(3)

###################### module main ##############################

