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
    LoadLibrary("advapi32.dll")

    hooks = [ ("advapi32.dll", "OpenSCManagerW", OpenSCManagerW_handler),
              ("advapi32.dll", "CreateServiceA", CreateServiceA_handler),
              ("advapi32.dll", "CreateServiceW", CreateServiceW_handler),
              ("advapi32.dll", "OpenServiceW", OpenServiceW_handler),
              ("advapi32.dll", "StartServiceW", StartServiceW_handler),
              ("advapi32.dll", "ControlService", ControlService_handler),
              ("advapi32.dll", "DeleteService", DeleteService_handler),
              ]

    for (dll_name, func_name, handler) in hooks:
        if not pybox.register_hook(dll_name,
                                   func_name,
                                   handler):
            logging.error("Failed to register hook for %s" % func_name)
            
    return

def OpenSCManagerW_handler(exec_ctx):
    """Callback for OpenSCManagerW"""
    args = exec_ctx.get_stack_args("uud")
    if args:
        logging.info("kernel32.dll.OpenSCManagerW(%s, %s, 0x%08x)" % args)

    return

def CreateServiceA_handler(exec_ctx):
    """Callback for CreateServiceA"""
    args = exec_ctx.get_stack_args("daaddddaadaaa")
    if args:
        logging.info("kernel32.dll.CreateServiceA(0x%08x, %s, %s, 0x%08x, " \
                         "0x%08x, 0x%08x, 0x%08x, %s, %s, 0x%08x, %s, %s, %s)" % args)

    return

def CreateServiceW_handler(exec_ctx):
    """Callback for CreateServiceW"""
    args = exec_ctx.get_stack_args("duudddduuduuu")
    if args:
        logging.info("kernel32.dll.CreateServiceW(0x%08x, %s, %s, 0x%08x, " \
                     "0x%08x, 0x%08x, 0x%08x, %s, %s, 0x%08x, %s, %s, %s)" % args)

    return

def OpenServiceW_handler(exec_ctx):
    """Callback for OpenServiceW"""
    args = exec_ctx.get_stack_args("dud")
    logging.info("kernel32.dll.OpenServiceW(0x%08x, %s, 0x%08x)" % args)

    return

def StartServiceW_handler(exec_ctx):
    """Callback for StartServiceW"""
    args = exec_ctx.get_stack_args("dud")
    logging.info("kernel32.dll.StartServiceW(0x%08x, %s, 0x%08x)" % args)

    return

def ControlService_handler(exec_ctx):
    """Callback for ControlService"""
    args = exec_ctx.get_stack_args("ddd")
    logging.info("kernel32.dll.ControlService(0x%08x, 0x%08x, 0x%08x)" % args)

    return

def DeleteService_handler(exec_ctx):
    """Callback for DeleteService"""
    args = exec_ctx.get_stack_args("d")
    logging.info("kernel32.dll.DeleteService(0x%08x)" % args)

    return
