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
#   basic collection of file system operations
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

    hooks = [ ("kernel32.dll", "CreateMutexW", CreateMutexW_handler),
              ("kernel32.dll", "OpenMutexW", OpenMutexW_handler),
              ("kernel32.dll", "ReleaseMutex", ReleaseMutex_handler),
              ]

    for (dll_name, func_name, handler) in hooks:
        if not pybox.register_hook(dll_name,
                                   func_name,
                                   handler):
            logging.error("Failed to register hook for %s" % func_name)
            
    return

def CreateMutexW_handler(exec_ctx):
    """Callback for CreateMutexW"""
    args = tuple(exec_ctx.get_stack_args("ddd"))
    if(args[2] == 0):
        logging.info("kernel32.dll.CreateMutexW(0x%08x, 0x%08x, 0x%08x" % args) 
    else:
        args = tuple(exec_ctx.get_stack_args("ddu"))
        logging.info("kernel32.dll.CreateMutexW(0x%08x, 0x%08x, %s" % args)

    return

def OpenMutexW_handler(exec_ctx):
    """Callback for OpenMutexW"""
    args = tuple(exec_ctx.get_stack_args("ddu"))
    logging.info("kernel32.dll.OpenMutexW(0x%08x, 0x%08x, %s" % args)

    return

def ReleaseMutex_handler(exec_ctx):
    """Callback for ReleaseMutex"""
    arg = tuple(exec_ctx.get_stack_args("d"))
    logging.info("kernel32.dll.ReleaseMutex(0x%08x" % arg)

    return
