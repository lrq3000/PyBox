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

    hooks = [ ("kernel32.dll", "CreateFileW", CreateFileW_handler),
              ("kernel32.dll", "CreateFileA", CreateFileA_handler),
              ("kernel32.dll", "CopyFileA", CopyFileA_handler),
              ("kernel32.dll", "CreateDirectoryA", CreateDirectoryA_handler),
              ("kernel32.dll", "DeleteFileA", DeleteFileA_handler),
              ("kernel32.dll", "fclose", fclose_handler),
              ("kernel32.dll", "fopen", fopen_handler),
              ("kernel32.dll", "fwrite", fwrite_handler),
              ("kernel32.dll", "GetSystemDirectoryA", GetSystemDirectoryA_handler),
              ("kernel32.dll", "GetTempPathA", GetTempPathA_handler),
              ("kernel32.dll", "_hwrite", hwrite_handler),
              ("kernel32.dll", "_lclose", lclose_handler),
              ("kernel32.dll", "_lcreat", lcreat_handler),
              ("kernel32.dll", "_lwrite", lwrite_handler),
              ("kernel32.dll", "MoveFileExW", MoveFileExW_handler),
              ("kernel32.dll", "ReadFile", ReadFile_handler),
              ("kernel32.dll", "WriteFile", WriteFile_handler),
              ]

    for (dll_name, func_name, handler) in hooks:
        if not pybox.register_hook(dll_name,
                                   func_name,
                                   handler):
            logging.error("Failed to register hook for %s" % func_name)
            
    return

def CreateFileW_handler(exec_ctx):
    """Callback for CreateFileW"""
    args = tuple(exec_ctx.get_stack_args("udddddd"))
    logging.info("kernel32.dll.CreateFileW(%s, 0x%08x, %d, %d, %d, 0x%08x," \
    "%d)" % args)

    return

def CreateFileA_handler(exec_ctx):
    """Callback for CreateFileA"""
    args = tuple(exec_ctx.get_stack_args("adddddd"))
    logging.info("kernel32.dll.CreateFileA(%s, 0x%08x, %d, %d, %d, 0x%08x," \
    "%d)" % args)

    return

def CopyFileA_handler(exec_ctx):
    """Callback for CopyFileA"""
    args = tuple(exec_ctx.get_stack_args("aad"))
    logging.info("kernel32.dll.CopyFileA(%s, %s, %d)" % args)

    return
        
def CreateDirectoryA_handler(exec_ctx):
    """Callback for CreateDirectoryA"""
    args = tuple(exec_ctx.get_stack_args("ad"))
    logging.info("kernel32.dll.CreateDirectoryA(%s, 0x%08x)" % args)   
    
    return   

def DeleteFileA_handler(exec_ctx):
    """Callback for DeleteFileA"""
    args = tuple(exec_ctx.get_stack_args("a"))
    logging.info("kernel32.dll.DeleteFileA(%s)" \
                     % args)
    
    return     

def fclose_handler(exec_ctx):
    logging.debug("fclose called")
    lclose_handler(exec_ctx)
        
    return
    
def fopen_handler(exec_ctx):
    logging.debug("fopen called")
    args = tuple(exec_ctx.get_stack_args("ad"))
    logging.info("fopen(%s, 0x%x)" \
                     % args)
    
    return
    
def fwrite_handler(exec_ctx):
    logging.debug("fwrite called")
    args = tuple(exec_ctx.get_stack_args("dddd"))
    logging.info("fwrite(0x%08x, 0x%08x, 0x%08x, 0x%08x)" \
                     % args)
    
    return
    
def GetSystemDirectoryA_handler(exec_ctx):
    logging.debug("GetSystemDirectoryA called")
    args = tuple(exec_ctx.get_stack_args("dd"))
    logging.info("kernel32.dll.GetSystemDirectoryA(0x%08x, 0x%08x)" \
                     % args)
        
    return
    
def GetTempPathA_handler(exec_ctx):
    logging.debug("GetTempPathA called")
    args = tuple(exec_ctx.get_stack_args("dd"))
    logging.info("kernel32.dll.GetTempPathA(0x%08x, 0x%08x)" \
                     % args)
    
    return
    
def hwrite_handler(exec_ctx):
    logging.debug("_hwrite called")
    lwrite_handler(exec_ctx)
    
    return
    
def lclose_handler(exec_ctx):
    logging.debug("_lclose called")
    arg = exec_ctx.get_arg(0)
    logging.info("close(0x%08x)" % arg)
    
    return
    
def lcreat_handler(exec_ctx):
    logging.debug("_lcreat called")
    args = tuple(exec_ctx.get_stack_args("ad"))
    logging.info("create(%s, 0x%x)" \
                     % args)
        
    return
    
def lwrite_handler(exec_ctx):
    logging.debug("_lwrite called")
    args = tuple(exec_ctx.get_stack_args("ddd"))
    logging.info("write(0x%08x, 0x%08x, %d)" % args)
      
    return
    
def MoveFileExW_handler(exec_ctx):
    logging.debug("MoveFileExW called")
    args = tuple(exec_ctx.get_stack_args("uud"))
    logging.info("kernel32.dll.MoveFileExW(%s, %s, 0x%08x)" \
                     % args)  
    
    return
    
def ReadFile_handler(exec_ctx):
    logging.debug("ReadFile called")
    args = tuple(exec_ctx.get_stack_args("ddddd"))
    logging.info("kernel32.dll.ReadFile(0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x)" \
                     % args)         
      
    return
    
def WriteFile_handler(exec_ctx):
    logging.debug("WriteFile called")
    args = tuple(exec_ctx.get_stack_args("ddddd"))
    logging.info("kernel32.dll.WriteFile(0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x)" \
                     % args)         
    
    return
    