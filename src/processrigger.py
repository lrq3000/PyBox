#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
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
Processrigger provides functionality for manipulating the properties of 
processes such as granting debugging privileges or enabling remote API calls.
Rights will be set accordingly if not set correctly.
"""

import injector_defines

from ctypes import sizeof, byref, c_int, c_ulong, wintypes
import ctypes
import sys
import struct

KERNEL_32 = ctypes.windll.kernel32
ADVAPI_32 = ctypes.windll.advapi32

def set_remote_allaccess(pid, address, num_bytes):
    """sets the permissions for the memory of the remote process,
    given by its pid, to readable, writeable, and executable.
    @param pid: Process id of remote process
    @type pid: int
    @param address: address to set per
    @type address: int
    @param num_bytes: Size of the memory region
    @type num_bytes: int
    @return: c{True} if successful, c{False} otherwise
    """

    addr = address
    end = address + num_bytes

    # opening remote process
    hprocess = KERNEL_32.OpenProcess(injector_defines.PROCESS_ALL_ACCESS,
                                     False,
                                     pid)
    if not hprocess:
        print >> sys.stderr, "Cannot open remote process (pid: %i) to set " \
                "memory permissions" % pid
        return False    

    while addr < end:

        # get information about current state    
        mbi = injector_defines.MEMORY_BASIC_INFORMATION()
        if KERNEL_32.VirtualQueryEx(hprocess,
                                    address,
                                    byref(mbi),
                                    sizeof(mbi)) == 0:
            print >> sys.stderr, "Cannot get info about memory of process " \
                "(pid) %i" % pid
            KERNEL_32.CloseHandle(hprocess)
            
            return False

        base = mbi.BaseAddress
        size = mbi.RegionSize

        if mbi.Protect != injector_defines.PAGE_EXECUTE_READWRITE:            
            # set new permissions
            old_permission_dummy = injector_defines.DWORD(0)
            if KERNEL_32.VirtualProtectEx(hprocess,
                                          base,
                                          size,
                                          injector_defines.PAGE_EXECUTE_READWRITE,
                                          byref(old_permission_dummy)) == 0:
                print >> sys.stderr, "Cannot set permission for memory " \
                        "of process (pid) %i" % pid
                KERNEL_32.CloseHandle(hprocess)
            
                return False            

        # continue with next memory page (if exists)
        addr = base + size
        
    KERNEL_32.CloseHandle(hprocess)
    
    return True


def grant_debug_privilege(pid = 0):
    """ grant SeDebugPrivilege to own process
    @param pid: Process id to set permissions of (or 0 if current)
    @type pid: int
    @return: True if operation was successful, 
              False otherwise
    """
    ADVAPI_32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, \
        ctypes.POINTER(wintypes.HANDLE))
    ADVAPI_32.LookupPrivilegeValueW.argtypes = (wintypes.LPWSTR, \
        wintypes.LPWSTR, ctypes.POINTER(injector_defines.LUID))
    ADVAPI_32.AdjustTokenPrivileges.argtypes = (wintypes.HANDLE, \
        wintypes.BOOL, ctypes.POINTER(injector_defines.TOKEN_PRIVILEGES), \
        wintypes.DWORD, ctypes.POINTER(injector_defines.TOKEN_PRIVILEGES), \
        ctypes.POINTER(wintypes.DWORD))

    # local or remote process?
    h_process = None
    if pid == 0:
        h_process = KERNEL_32.GetCurrentProcess()
    else:
        h_process = KERNEL_32.OpenProcess(injector_defines.PROCESS_ALL_ACCESS,
                                          False,
                                          pid)
    
    if not h_process:
        print >> sys.stderr, "Failed to open process for setting debug privileges" \
              % pid
        return False    

    
    # obtain token to process
    h_current_token = wintypes.HANDLE() 
    if not ADVAPI_32.OpenProcessToken(h_process, \
               injector_defines.TOKEN_ALL_ACCESS, h_current_token): 
        print >> sys.stderr, "Did not obtain process token."
        return False
    
    # look up current privilege value
    se_original_luid = injector_defines.LUID()
    if not ADVAPI_32.LookupPrivilegeValueW(None, "SeDebugPrivilege", \
               se_original_luid):
        print >> sys.stderr, "Failed to lookup privilege value."
        return False

    luid_attributes = injector_defines.LUID_AND_ATTRIBUTES()
    luid_attributes.Luid = se_original_luid
    luid_attributes.Attributes = injector_defines.SE_PRIVILEGE_ENABLED
    token_privs = injector_defines.TOKEN_PRIVILEGES()
    token_privs.PrivilegeCount=1;
    token_privs.Privileges=luid_attributes; 
    
    if not ADVAPI_32.AdjustTokenPrivileges(h_current_token, False, \
               token_privs, 0, None, None):
        print >> sys.stderr, "Failed to grant SE_DEBUG_PRIVILEGE to self."
        return False
    
    KERNEL_32.CloseHandle(h_current_token)
    KERNEL_32.CloseHandle(h_process)
    
    return True


class RemoteApiCallArgument(object):
    """Class objects provide information about an API call argument"""
    
    is_immediate = True
    arg_value = 0
    offset = 0

    def __init__(self, imm, value):
        """Constructor.
        @param imm: decides whether passed parameter is treated as 
                    immediate value or not
        @type imm: Boolean
        @param value: value of argument to set
        @type value: depends on argument type
        """
        self.arg_value = value
        if imm:
            self.is_immediate = True
        else:
            self.is_immediate = False


def remote_api_call(pid, library, api_call, arguments):
    """ EXPERIMENTAL: Perform arbitrary API call in a remote process.
    This is based on the assumption that target DLL is loaded at same address
    as in the local process.
    @param pid: pid (decimal) to perform API call in 
    @type pid: int
    @param library: library providing the API call
    @type library: string  
    @param name: name of target API call
    @type name: string  
    @param arguments: arguments to the API call
    @type value: RemoteApiCallArgument[]                    
    @return: True if operation was successful, 
              False otherwise
    """
    h_process = KERNEL_32.OpenProcess(injector_defines.PROCESS_ALL_ACCESS, \
                            False, int(pid))
    if not h_process:
        print >> sys.stderr, "Cannot access process (PID): %s" % pid
        return False
    
    virtual_mem = (injector_defines.MEM_COMMIT | injector_defines.MEM_RESERVE)
    
    # prepare referenced API call arguments and write them to remote process
    # use two zero bytes as general terminator to handle all types of
    # arguments
    args = ""
    for arg in arguments:
        if not arg.is_immediate:
            arg.offset = len(args)
            args = args + arg.arg_value + "\0\0"
    
    args_base_address = KERNEL_32.VirtualAllocEx(h_process, 0, len(args), \
                            virtual_mem, injector_defines.PAGE_READWRITE)
    if args_base_address == 0:
        print >> sys.stderr, "Failed to reserve memory for arguments."
        return False
        
    bytes_written = c_int(0)
    
    if not KERNEL_32.WriteProcessMemory(h_process, args_base_address, args, \
                            len(args), byref(bytes_written)):
        print >> sys.stderr, "ERROR: Failed to write arguments."
        return False
    
    # obtain handles for remote call
    KERNEL_32.LoadLibraryA(library)
    h_library = KERNEL_32.GetModuleHandleA(library)
    h_kernel_32 = KERNEL_32.GetModuleHandleA("kernel32.dll")
    h_api_call = KERNEL_32.GetProcAddress(h_library, \
                            api_call)
    h_exitthreat = KERNEL_32.GetProcAddress(h_kernel_32, "ExitThread")
    
    # prepare memory for remote API call
    # 5 * number arguments (these need to be pushed on the stack)
    # plus 15 static bytes:
    # 5    call TARGET_API
    # 5    push 0
    # 5    call ExitThread
    r_api_call_len = 15 + 5 * len(arguments)
    r_api_call_address = KERNEL_32.VirtualAllocEx(h_process, 0, \
                              r_api_call_len, virtual_mem, \
                              injector_defines.PAGE_READWRITE)
    if r_api_call_address == 0:
        print >> sys.stderr, "Failed to reserve memory for code to inject."
        return False
    
    # set shellcode to perform in remote thread
    r_api_call_content = ""
    # push API call arguments to stack
    # 0x68 is assembler instruction for "push dword"
    # Reverse order of arguments in assumption it is a STDCALL or CDECL call
    for arg in reversed(arguments):
        r_api_call_content += "\x68"
        if arg.is_immediate:
            # push immediate parameter (4 bytes)
            r_api_call_content += struct.pack("I", arg.arg_value)
        else:
            # push absolute address of referenced parameter (4 bytes)
            # use offset calculated earlier
            arg_address = args_base_address + arg.offset
            r_api_call_content += struct.pack("I", arg_address)
    # write API call itself
    # 0xE8 is assembler instruction for "far call dword"
    r_api_call_content += "\xE8"
    relative_callback = h_api_call - \
                                (r_api_call_address + \
                                 len(r_api_call_content) + 4)
    r_api_call_content  += struct.pack("I", relative_callback)
    # write argument "0" for ExitThread to allow clean termination
    r_api_call_content += "\x68"
    r_api_call_content += struct.pack("I", 0)
    # write call to ExitThread
    r_api_call_content += "\xE8"
    relative_callback = h_exitthreat - \
                                (r_api_call_address + \
                                 len(r_api_call_content) + 4)
    r_api_call_content  += struct.pack("I", relative_callback)
    
    # write code to remote process memory and perform API call
    KERNEL_32.WriteProcessMemory(h_process, r_api_call_address, \
                            r_api_call_content, len(r_api_call_content), \
                            byref(bytes_written))
    
    new_thread_id = c_ulong(0)
    
    if not set_remote_allaccess(pid,
                                 r_api_call_address,
                                 len(r_api_call_content)):
        print >> sys.stderr, "Cannot call %s.%s in process (pid) %i" % \
              (library, api_call, pid)
        return False
    
    if not KERNEL_32.CreateRemoteThread(h_process,
                                       None,
                                       0,
                                       r_api_call_address,
                                       None,
                                       0,
                                       byref(new_thread_id)):
        print >> sys.stderr, "ERROR: Injection failed"
        return False
    
    return True


def set_remote_env_var(pid, name, value):
    """ Set a environment variable in a remote process
    @param pid: pid (decimal) to write the environment variable to 
    @type pid: int
    @param name: name of environment variable to set
    @type name: string  
    @param value: value of environment variable to set
    @type value: string                    
    @return: True if operation was successful, 
              False otherwise
    """
    arg_name = RemoteApiCallArgument(False, name)
    arg_value = RemoteApiCallArgument(False, value)
    if not remote_api_call(pid, "kernel32.dll", "SetEnvironmentVariableA", \
                    [arg_name, arg_value]):
        print >> sys.stderr, "ERROR: Call to SetEnvironmentVariable failed"
        return False
    
    return True
