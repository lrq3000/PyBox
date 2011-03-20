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
#   basic collection of hooks for registry
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
    LoadLibrary("advapi32.dll")

    hooks = [ ("advapi32.dll", "RegCreateKeyW", RegCreateKeyW_handler),
              ("advapi32.dll", "RegDeleteKeyW", RegDeleteKeyW_handler),
              ("advapi32.dll", "RegEnumKeyExW", RegEnumKeyExW_handler),
              ("advapi32.dll", "RegEnumValueW", RegEnumValueW_handler),
              ("advapi32.dll", "RegOpenKeyExW", RegOpenKeyExW_handler),
              ("advapi32.dll", "RegSetValueExW", RegSetValueExW_handler),
              ("advapi32.dll", "RegSetKeyValueW", RegSetKeyValueW_handler),
              ]

    for (dll_name, func_name, handler) in hooks:
        if not pybox.register_hook(dll_name,
                                   func_name,
                                   handler):
            logging.error("Failed to register hook for %s" % func_name)
            
    return

def RegCreateKeyW_handler(exec_ctx):
    """Callback for RegCreateKeyEx"""
    args = tuple(exec_ctx.get_stack_args("dudddddpd"))
    logging.info("advapi32.dll.RegCreateKeyW(0x%x, %s, %d, %d, %d, %d, %d, " \
                 "%d, %d)" % args)
    
    return
    
def RegDeleteKeyW_handler(exec_ctx):
    """Callback for RegDeleteKeyW"""
    args = tuple(exec_ctx.get_stack_args("du"))
    logging.info("advapi32.dll.RegDeleteKeyW(0x%08x, %s)" % args)   
     
    return
       
def RegEnumKeyExW_handler(exec_ctx):
    """Callback for RegOpenKeyEx"""
    args = tuple(exec_ctx.get_stack_args("dduddudd"))
    logging.info("advapi32.dll.RegEnumKeyExW(%d, %d, %s, %d, %d, %s, %d, " \
                 "%d)" % args)
       
    return
     
def RegEnumValueW_handler(exec_ctx):
    """Callback for RegEnumValueW"""
    args = tuple(exec_ctx.get_stack_args("dduddddd"))
    logging.info("advapi32.dll.RegEnumValueW(%d, %d, %s, %d, %d, %d, %d, \ "
                 "%d)" % args)
    
    return
    
def RegOpenKeyExW_handler(exec_ctx):
    """Callback for RegOpenKeyExW"""
    args = tuple(exec_ctx.get_stack_args("ddddd"))
    if(args[1] == 0):
        logging.info("advapi32.dll.RegOpenKeyExW(0x%08x, 0x%08x, 0x%08x, " \
                     "0x%08x, 0x%08x)" % args)
    else:
        args = tuple(exec_ctx.get_stack_args("duddd"))
        logging.info("advapi32.dll.RegOpenKeyExW(0x%08x, %s, 0x%08x, 0x%08x, " \
                     "0x%08x)" % args)
        
    return
    
def RegSetValueExW_handler(exec_ctx):
    """Callback for RegOpenKeyExW"""
    args = tuple(exec_ctx.get_stack_args("duddud"))
    logging.info("advapi32.dll.RegOpenKeyExW(0x%x, %s, %d, %d, %s, %d)" % args)
        
    return
    
def RegSetKeyValueW_handler(exec_ctx):
    """Callback for RegSetKeyValueW"""
    args = tuple(exec_ctx.get_stack_args("duudud"))
    logging.info("advapi32.dll.RegSetKeyValueW(%d, %s, %s, %d, %s, %d)" % args)
        
    return
    