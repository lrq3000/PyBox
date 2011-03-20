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
#   basic collection of hooks for network operations
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

import logging
from ctypes import Structure, c_short, c_ushort, c_ubyte
import ctypes
import pybox

def init():
    """Initialize all hooks/handlers defined in this file"""
    
    # ensure that required libraries are loaded
    LoadLibrary = ctypes.windll.kernel32.LoadLibraryA
    GetProcAddress = ctypes.windll.kernel32.GetProcAddress
    LoadLibrary("ws2_32.dll")
    LoadLibrary("wininet.dll")
    t = LoadLibrary("urlmon.dll")
    logging.debug("urlmon %x" % GetProcAddress(t, "URLDownloadToFileA"))

    hooks = [ ("ws2_32.dll", "accept", accept_handler),
              ("ws2_32.dll", "bind", bind_handler),
              ("ws2_32.dll", "closesocket", closesocket_handler),
              ("ws2_32.dll", "connect", connect_handler),
              ("wininet.dll", "InternetOpenUrlW", InternetOpenUrlW_handler),
              ("ws2_32.dll", "listen", listen_handler),
              ("ws2_32.dll", "recv", recv_handler),
              ("ws2_32.dll", "recvfrom", recvfrom_handler),
              ("ws2_32.dll", "send", send_handler),
              ("ws2_32.dll", "sendto", sendto_handler),
              ("ws2_32.dll", "socket", socket_handler),
              ("ws2_32.dll", "WSASocketA", WSASocketA_handler),
              ("ws2_32.dll", "WSAStartup", WSAStartup_handler),
              ("urlmon.dll", "URLDownloadToFileA", URLDownloadToFileA_handler),
              ]

    for (dll_name, func_name, handler) in hooks:
        if not pybox.register_hook(dll_name,
                                   func_name,
                                   handler):
            logging.error("Failed to register hook for %s" % func_name)
            
    return     

class in_addr(Structure):
    _fields_ = [
        ("s_addr", c_ubyte * 4)
        ]

class sockaddr_in(Structure):
    _fields_ = [
        ("sin_family",      c_short),
        ("sin_port",        c_ushort),
        ("sin_addr",        in_addr),
    ]

def parse_sockaddr_in(addr):
    if addr == 0:
        return "?.?.?.?:??"

    psin = cast(addr, POINTER(sockaddr_in))
    sin = psin.contents
        
    ip = sin.sin_addr.s_addr
    return "%d.%d.%d.%d:%d" % (ip[0],
                               ip[1],
                               ip[2],
                               ip[3],
                               sin.sin_port)   
    
def accept_handler(exec_ctx):
    logging.debug("accept called")
    args = tuple(exec_ctx.get_stack_args("ddp"))
    ip_addr = parse_sockaddr_in(args[1])
    logging.info("accept(0x%08x, %s, %d)" %
                 (args[0], ip_addr, args[2]))
    
    return
    
def bind_handler(exec_ctx):
    logging.debug("bind called")
    args = tuple(exec_ctx.get_stack_args("ddp"))
    ip_addr = parse_sockaddr_in(args[1])
    logging.info("bind(0x%08x, %s, %d)" %
                 (args[0], ip_addr, args[2]))
    
    return
    
def closesocket_handler(exec_ctx):
    logging.debug("closesocket called")
    arg = exec_ctx.get_arg(0)
    logging.info("closesocket(0x%08x)" % arg)
    
    return
    
def connect_handler(exec_ctx):
    """Callback for connect"""
    args = tuple(exec_ctx.get_stack_args("ddd"))
    ip_addr = parse_sockaddr_in(args[1])
    logging.info("ws2_32.dll.connect(%d, %s, %d)" % args[0], ip_addr, args[2])
    
    return
    
def InternetOpenUrlW_handler(exec_ctx):
    logging.debug("InternetOpenUrlW called")
    args = tuple(exec_ctx.get_stack_args("duuddd"))
    logging.info("InternetOpenUrlW(0x%08x, %s, %s, %d, 0x%08x, 0x%08x)" \
                     % args)
    return

def listen_handler(exec_ctx):
    args = tuple(exec_ctx.get_stack_args("dd"))
    logging.info("InternetOpenUrlW(0x%08x, %d)" % args)
        
    return
    
def recv_handler(exec_ctx):
    """Callback for recv"""
    args = tuple(exec_ctx.get_stack_args("dadd"))
    logging.info("ws2_32.dll.recv(%d, %s, %d, %d)" % args)
        
    return
    
def recvfrom_handler(exec_ctx):
    """Callback for recvfrom"""
    args = tuple(exec_ctx.get_stack_args("dadddp"))
    ip_addr = parse_sockaddr_in(args[4])
    logging.info("ws2_32.dll.recvfrom(%d, %s, %d, %d, %d, %d)" % (\
                 args[0],
                 args[1],
                 args[2],
                 args[3],
                 ip_addr,
                 args[5]
                 ))
        
    return
    
def send_handler(exec_ctx):
    """Callback for send"""
    args = tuple(exec_ctx.get_stack_args("dadd"))
    logging.info("ws2_32.dll.send(%d, %s, %d, 0x%08x)" % args)
        
    return
    
def sendto_handler(exec_ctx):
    """Callback for sendto"""
    args = tuple(exec_ctx.get_stack_args("dadddd"))
    ip_addr = parse_sockaddr_in(args[4])
    logging.info("ws2_32.dll.sendto(%d, %s, %d, %d, %d, %d)" % (\
                args[0],
                args[1],
                args[2],
                args[3],
                ip_addr,
                args[5]
                ))
        
    return
    
def socket_handler(exec_ctx):
    logging.debug("socket called")
    args = tuple(exec_ctx.get_stack_args("ddd"))
    logging.info("ws2_32.dll.socket(0x%08x, 0x%08x, 0x%08x)" % args)
    
    return
    
def WSASocketA_handler(exec_ctx):
    logging.debug("ws2_32.dll.WSASocketA called")
    socket_handler(exec_ctx)
    
    return
    
def WSAStartup_handler(exec_ctx):
    args = tuple(exec_ctx.get_stack_args("dd"))
    logging.info("ws2_32.dll.WSAStartup(0x%08x, 0x%08x)" % args)
    
    
    return
    
def URLDownloadToFileA_handler(exec_ctx):
    logging.debug("URLDownloadToFileA called")
    args = tuple(exec_ctx.get_stack_args("daadd"))
    logging.info("URLDownloadToFileA(0x%08x, %s, %x, 0x%08x, 0x%08x)" \
                     % args)
    return