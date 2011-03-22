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
#   basic collection of hooks for processes and threads
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

import os
import logging
import ctypes

import pybox

def init(): 
    """Initialize all hooks/handlers defined in this file"""
    
    # ensure that required libraries are loaded
    LoadLibrary = ctypes.windll.kernel32.LoadLibraryA
    LoadLibrary("kernel32.dll")
    LoadLibrary("msvcrt.dll")

    hooks = [ ("kernel32.dll", "CloseHandle", CloseHandle_handler),
              ("kernel32.dll", "CreateProcessA", CreateProcessA_handler),
              ("kernel32.dll", "CreateProcessW", CreateProcessW_handler),
              ("kernel32.dll", "CreateRemoteThread", CreateRemoteThread_handler),
              ("kernel32.dll", "CreateThread", CreateThread_handler),
              ("kernel32.dll", "ExitProcess", ExitProcess_handler),
              ("kernel32.dll", "ExitThread", ExitThread_handler),
              ("msvcrt.dll", "_execv", execv_handler),
              ("kernel32.dll", "GetTickCount", GetTickCount_handler),
              ("kernel32.dll", "OpenProcess", OpenProcess_handler),
              ("kernel32.dll", "SetUnhandledExceptionFilter",\
                SetUnhandledExceptionFilter_handler),
              ("kernel32.dll", "ShellExecuteA", ShellExecuteA_handler),
              ("kernel32.dll", "ShellExecuteW", ShellExecuteW_handler),
              ("kernel32.dll", "Sleep", Sleep_handler),
              ("kernel32.dll", "TerminateProcess", TerminateProcess_handler),
              ("kernel32.dll", "WaitForSingleObject", \
               WaitForSingleObject_handler),
              ("kernel32.dll", "WinExec", WinExec_handler),
              ]

    for (dll_name, func_name, handler) in hooks:
        if not pybox.register_hook(dll_name,
                                   func_name,
                                   handler):
            logging.error("Failed to register hook for %s" % func_name)
            
    return
        
def CloseHandle_handler(exec_ctx):
    """Callback for CloseHandle"""
    logging.debug("CloseHandle called")
    arg = exec_ctx.get_arg(0)
    logging.info("kernel32.dll.CloseHandle(0x%08x)" % arg)  
    
    return              
             
def CreateProcessA_handler(exec_ctx):
    """Callback for CreateProcessA"""
    args = tuple(exec_ctx.get_stack_args("aadddddadd"))
    logging.info("kernel32.dll.CreateProcessA(%s, %s, %d, %d, %d, %d, %d, "
                 "%s, %d, %d)" % args)
    
    return

def CreateProcessW_handler(exec_ctx):
    """Callback for CreateProcessW"""
    args = tuple(exec_ctx.get_stack_args("uudddddudd"))
    logging.info("kernel32.dll.CreateProcessA(%s, %s, %d, %d, %d, %d, %d, "
                 "%s, %d, %d)" % args)
    
    return

def CreateRemoteThread_handler(exec_ctx):
    """Callback for CreateRemoteThread"""
    args = tuple(exec_ctx.get_stack_args("dddddddd"))
    logging.info("kernel32.dll.CreateRemoteThread(0x%08x, 0x%08x, 0x%08x, " \
                 "0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x)" % args)
    
    return
    
def CreateThread_handler(exec_ctx):
    """Callback for CreateThread"""
    args = tuple(exec_ctx.get_stack_args("dddddd"))
    logging.info("kernel32.dll.CreateThread(%d, %d, %d, %d, %d, %d)" \
                 % args)
    return

def ExitProcess_handler(exec_ctx):
    """Callback for ExitProcess"""
    logging.debug("ExitProcess called")
    arg = exec_ctx.get_arg(0)
    logging.info("ExitProcess(0x%x)" % arg)
        
    return    

def ExitThread_handler(exec_ctx):
    """Callback for ExitProcess"""
    logging.debug("ExitProcess called")
    arg = exec_ctx.get_arg(0)
    logging.info("ExitProcess(0x%x)" % arg)
    
    return

def execv_handler(exec_ctx):
    """Callback for _execv"""
    logging.debug("_execv called")
    args = tuple(exec_ctx.get_stack_args("a"))
    logging.info("_execv(%s, ...)" % args)
     
    return    
   
def GetTickCount_handler(exec_ctx):
    """Callback for GetTickCount"""
    logging.debug("GetTickCount called")
        
    return

def OpenProcess_handler(exec_ctx):
    """Callback for OpenProcessW"""
    args = tuple(exec_ctx.get_stack_args("ddd"))
    pid = os.getpid()
    if (args[2] != pid):
        logging.info("kernel32.dll.OpenProcess accessing external process!")
    logging.info("kernel32.dll.OpenProcessW(0x%08x, %d, 0x%08x)" \
                 % args)
    
    if not pybox.register_return_hook("OpenProcessW_return", exec_ctx, \
    OpenProcess_rtn_handler):
        logging.error("Cannot install return hook for OpenProcessW")

    return

def OpenProcess_rtn_handler(exec_ctx):
    """Return callback for OpenProcessW"""
    logging.info("kernel32.dll.OpenProcessW returned 0x%08x" % exec_ctx.regs.EAX)
    
    return
    
def SetUnhandledExceptionFilter_handler(exec_ctx):
    arg = tuple(exec_ctx.get_stack_args("d"))
    logging.info("kernel32.dll.SetUnhandledExceptionFilter(0x%08x)" % arg)
    
    return
    
def ShellExecuteA_handler(exec_ctx):
    """Callback for ShellExecuteA"""
    args = tuple(exec_ctx.get_stack_args("daaaad"))
    logging.info("Shell32.dll.ShellExecuteA(%d, %s, %s, %s, %s, %d)" \
                 % args)
    
    return
    
def ShellExecuteW_handler(exec_ctx):
    """Callback for ShellExecuteW"""
    args = tuple(exec_ctx.get_stack_args("daaaad"))
    logging.info("Shell32.dll.ShellExecuteW(%d, %s, %s, %s, %s, %d)" \
                 % args)
    
    return

def Sleep_handler(exec_ctx):
    """Callback for Sleep"""
    arg = tuple(exec_ctx.get_stack_args("d"))
    logging.info("kernel32.dll.Sleep(%d)" % arg)
    
    return

def TerminateProcess_handler(exec_ctx):
    """Callback for TerminateProcess"""
    args = tuple(exec_ctx.get_stack_args("dd"))
    logging.info("kernel32.dll.TerminateProcess(%d, %d)" % args)
    
    return

def WaitForSingleObject_handler(exec_ctx):
    """Callback for WaitForSingleObject"""
    args = tuple(exec_ctx.get_stack_args("dd"))
    logging.info("kernel32.dll.WaitForSingleObject(0x%08x, 0x%08x)" % args)
    
    return    

def WinExec_handler(exec_ctx):
    """Callback for WinExec"""
    logging.debug("WinExec called")
    args = tuple(exec_ctx.get_stack_args("ad"))
    logging.info("WinExec(%s, 0x%08x)" % args)
    
    return