#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:       $Id: basic_hooks.py 33 2010-07-19 14:14:21Z plohmann $
########################################################################
# Description:
#   basic collection of hooks for memory operations
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

"""Basic collection of interesting API functions"""


import pybox
import logging
import ctypes

def init():
    """Initialize all hooks/handlers defined in this file"""
    
    # ensure that required libraries are loaded
    LoadLibrary = ctypes.windll.kernel32.LoadLibraryA
    LoadLibrary("kernel32.dll")

    hooks = [ ("kernel32.dll", "LoadLibraryA", LoadLibraryA_handler),
              ("kernel32.dll", "GetProcAddress", GetProcAddress_handler),
              ("kernel32.dll", "malloc", malloc_handler),
              ("kernel32.dll", "memset", memset_handler),
              ("kernel32.dll", "ReadProcessMemory", ReadProcessMemory_handler),
              ("kernel32.dll", "VirtualAllocEx", VirtualAllocEx_handler),
              ("kernel32.dll", "WriteProcessMemory", \
               WriteProcessMemory_handler),
              ]

    for (dll_name, func_name, handler) in hooks:
        if not pybox.register_hook(dll_name,
                                   func_name,
                                   handler):
            logging.error("Failed to register hook for %s" % func_name)
            
    return

def LoadLibraryA_handler(exec_ctx):
    """Callback for LoadLibraryA"""
    arg = exec_ctx.get_stack_args("a")
    logging.info("kernel32.dll.LoadLibraryA(%s)" % arg)

    if not pybox.register_return_hook("LoadLibraryA_return", exec_ctx, 
    LoadLibraryA_rtn_handler):
        logging.error("Cannot install return hook for LoadLibraryA")

    return


def LoadLibraryA_rtn_handler(exec_ctx):
    """Return callback for LoadLibraryA"""
    logging.info("kernel32.dll.LoadLibraryA returned 0x%08x" % \
                 exec_ctx.regs.EAX)
    
    # TODO: check / update list of hooks also
    pybox.MODULES.update()
    return


def GetProcAddress_handler(exec_ctx):
    """Callback for GetProcAddress"""
    args = tuple(exec_ctx.get_stack_args("dd"))
    if(args[1] < 0x4000):
        logging.info("kernel32.dll.GetProcAddress(0x%08x, 0x%08x)" \
                 % args)
    else:
        args = tuple(exec_ctx.get_stack_args("da"))
        logging.info("kernel32.dll.GetProcAddress(0x%08x, %s)" \
                     % args)
    
    return       

def malloc_handler(exec_ctx):
    logging.debug("malloc called")
    args = tuple(exec_ctx.get_stack_args("d"))
    logging.info("msvcrt.dll.malloc(%d)" % args) 

    return

def memset_handler(exec_ctx):
    logging.debug("memset called")
    args = tuple(exec_ctx.get_stack_args("pdd"))
    logging.info("msvcrt.dll.memset(0x%08x, 0x%x, %d)" % args) 
    
    return

def ReadProcessMemory_handler(exec_ctx):
    """Callback for ReadProcessMemory"""
    args = tuple(exec_ctx.get_stack_args("ddddd"))
    logging.info("kernel32.dll.ReadProcessMemory(0x%08x, 0x%08x, 0x%08x, " \
                 "%d, %d)" % args)
    
    return

def VirtualAllocEx_handler(exec_ctx):
    """Callback for VirtualAllocEx"""
    args = tuple(exec_ctx.get_stack_args("ddddd"))
    logging.info("kernel32.dll.VirtualAllocEx(0x%08x, 0x%08x, 0x%08x, " \
                 "0x%08x, 0x%08x)" % args)
    
    return
 
def VirtualProtect_handler(exec_ctx):
    logging.debug("VirtualProtect called")
    args = tuple(exec_ctx.get_stack_args("dddd"))
    logging.info("kernel32.dll.VirtualProtect(0x%08x, 0x%08x, 0x%08x, 0x%08x)" \
                     % args)   
    
def WriteProcessMemory_handler(exec_ctx):
    """Callback for WriteProcessMemory"""
    args = tuple(exec_ctx.get_stack_args("ddddd"))
    logging.info("kernel32.dll.WriteProcessMemory(0x%08x, 0x%08x, 0x%08x, " \
                 "%d, 0x%08x)" % args)
    
    return
