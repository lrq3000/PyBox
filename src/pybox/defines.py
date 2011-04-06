#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:
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

import struct
from ctypes import c_ubyte, c_ushort, c_ulong, POINTER, c_char, c_void_p, \
     c_int, Structure, Union


# Let's map the Microsoft types to ctypes for clarity
BYTE      = c_ubyte
WORD      = c_ushort
DWORD     = c_ulong
LPBYTE    = POINTER(c_ubyte)
LPTSTR    = POINTER(c_char) 
HANDLE    = c_void_p
PVOID     = c_void_p
LPVOID    = c_void_p
UINT_PTR  = c_ulong
SIZE_T    = c_ulong
HMODULE   = c_ulong
NULL = c_int(0)

#CreateToolhelp32Snapshot
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPTHREAD = 0x00000004

# Constants
DEBUG_PROCESS         = 0x00000001
CREATE_NEW_CONSOLE    = 0x00000010
CREATE_SUSPENDED      = 0x00000004
DBG_CONTINUE          = 0x00010002
INFINITE              = 0xFFFFFFFF
PROCESS_ALL_ACCESS    = 0x001F0FFF

# Debug event constants
EXCEPTION_DEBUG_EVENT      =    0x1
CREATE_THREAD_DEBUG_EVENT  =    0x2
CREATE_PROCESS_DEBUG_EVENT =    0x3
EXIT_THREAD_DEBUG_EVENT    =    0x4
EXIT_PROCESS_DEBUG_EVENT   =    0x5
LOAD_DLL_DEBUG_EVENT       =    0x6
UNLOAD_DLL_DEBUG_EVENT     =    0x7
OUTPUT_DEBUG_STRING_EVENT  =    0x8
RIP_EVENT                  =    0x9

# debug exception codes.
EXCEPTION_ACCESS_VIOLATION     = 0xC0000005
EXCEPTION_BREAKPOINT           = 0x80000003
EXCEPTION_GUARD_PAGE           = 0x80000001
EXCEPTION_SINGLE_STEP          = 0x80000004

# Thread constants for CreateToolhelp32Snapshot()
TH32CS_SNAPHEAPLIST = 0x00000001
TH32CS_SNAPPROCESS  = 0x00000002
TH32CS_SNAPTHREAD   = 0x00000004
TH32CS_SNAPMODULE   = 0x00000008
TH32CS_INHERIT      = 0x80000000
TH32CS_SNAPALL      = (TH32CS_SNAPHEAPLIST | TH32CS_SNAPPROCESS | \
                       TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE)
THREAD_ALL_ACCESS   = 0x001F03FF

# Context flags for GetThreadContext()
CONTEXT_FULL                   = 0x00010007
CONTEXT_DEBUG_REGISTERS        = 0x00010010

# Memory permissions
PAGE_EXECUTE_READWRITE         = 0x00000040
PAGE_EXECUTE                   = 0x10
PAGE_EXECUTE_READ              = 0x20
PAGE_READONLY                  = 0x02
PAGE_READWRITE                 = 0x04

# Hardware breakpoint conditions
HW_ACCESS                      = 0x00000003
HW_EXECUTE                     = 0x00000000
HW_WRITE                       = 0x00000001

# Memory Allocation Type

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_RESET = 0x80000


# Memory page permissions, used by VirtualProtect()
PAGE_NOACCESS                  = 0x00000001
PAGE_READONLY                  = 0x00000002
PAGE_READWRITE                 = 0x00000004
PAGE_WRITECOPY                 = 0x00000008
PAGE_EXECUTE                   = 0x00000010
PAGE_EXECUTE_READ              = 0x00000020
PAGE_EXECUTE_READWRITE         = 0x00000040
PAGE_EXECUTE_WRITECOPY         = 0x00000080
PAGE_GUARD                     = 0x00000100
PAGE_NOCACHE                   = 0x00000200
PAGE_WRITECOMBINE              = 0x00000400

class MODULEENTRY32(Structure):
    """ 
    Structures for CreateToolhelp32Snapshot 
    describes layout of module snapshot entry
    """
    _fields_ = [
        ("dwSize",         DWORD), 
        ("th32ModuleID",   DWORD),         
        ("th32ProcessID",  DWORD),
        ("GlblcntUsage",   DWORD),
        ("ProccntUsage",   DWORD),
        ("modBaseAddr",    c_void_p),
        ("modBaseSize",    c_void_p),
        ("hModule",           HMODULE),
        ("szModule",       c_char * 256),
        ("szExePath",      c_char * 260),    
        ]
    
    
class STARTUPINFO(Structure):
    """
    Structures for CreateProcessA() function
    STARTUPINFO describes how to spawn the process
    """
    _fields_ = [
        ("cb",            DWORD),        
        ("lpReserved",    LPTSTR), 
        ("lpDesktop",     LPTSTR),  
        ("lpTitle",       LPTSTR),
        ("dwX",           DWORD),
        ("dwY",           DWORD),
        ("dwXSize",       DWORD),
        ("dwYSize",       DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags",       DWORD),
        ("wShowWindow",   WORD),
        ("cbReserved2",   WORD),
        ("lpReserved2",   LPBYTE),
        ("hStdInput",     HANDLE),
        ("hStdOutput",    HANDLE),
        ("hStdError",     HANDLE),
        ]
    
class SECURITY_ATTRIBUTES(Structure):
    """
    Structures for CreateProcessA() function
    SECURITY_ATTRIBUTES contains the used security description
    """
    _fields_ = [
        ("nLength",            DWORD),        
        ("lpSecurityDescriptor",    LPVOID), 
        ("bInheritHandle",     DWORD),  
        ]

class PROCESS_INFORMATION(Structure):
    """
    PROCESS_INFORMATION receives its information
    after the target process has been successfully
    started.
    """
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
        ]

class EXCEPTION_RECORD(Structure):
    """
    When the dwDebugEventCode is evaluated
    """ 
    pass
    
EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]

class _EXCEPTION_RECORD(Structure):
    """
    information relevant for the definition of an exception 
    """
    _fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]

class EXCEPTION_DEBUG_INFO(Structure):
    """
    additional debugging information for an exception
    """
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("dwFirstChance",      DWORD),
        ]

class DEBUG_EVENT_UNION(Union):
    """
    this Union is populated by the debugging information for exceptions 
    """
    _fields_ = [
        ("Exception",         EXCEPTION_DEBUG_INFO),
#        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
#        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
#        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
#        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
#        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
#        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
#        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
#        ("RipInfo",           RIP_INFO),
        ]   

class DEBUG_EVENT(Structure):
    """
    this structure describes a debugging event that was trapped by a debugger 
    """
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId",      DWORD),
        ("dwThreadId",       DWORD),
        ("u",                DEBUG_EVENT_UNION),
        ]

class FLOATING_SAVE_AREA(Structure):
    """
    used by the CONTEXT structure
    """
    _fields_ = [
   
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
]

class CONTEXT(Structure):
    """
    this structure holds all values of thread context
    including register values, segment fields
    """
    _fields_ = [
    
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
]

class THREADENTRY32(Structure):
    """
    contains information about a thread
    we use this for enumerating all of the system threads
    """
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]

class PROC_STRUCT(Structure):
    """
    Supporting struct for the SYSTEM_INFO_UNION union
    """
    _fields_ = [
        ("wProcessorArchitecture",    WORD),
        ("wReserved",                 WORD),
]


class SYSTEM_INFO_UNION(Union):
    """
    Supporting union for the SYSTEM_INFO struct
    """
    _fields_ = [
        ("dwOemId",    DWORD),
        ("sProcStruc", PROC_STRUCT),
]
    
class SYSTEM_INFO(Structure):
    """
    SYSTEM_INFO structure is populated when a call to 
    kernel32.GetSystemInfo() is made. We use the dwPageSize
    member for size calculations when setting memory breakpoints
    """
    _fields_ = [
        ("uSysInfo", SYSTEM_INFO_UNION),
        ("dwPageSize", DWORD),
        ("lpMinimumApplicationAddress", LPVOID),
        ("lpMaximumApplicationAddress", LPVOID),
        ("dwActiveProcessorMask", DWORD),
        ("dwNumberOfProcessors", DWORD),
        ("dwProcessorType", DWORD),
        ("dwAllocationGranularity", DWORD),
        ("wProcessorLevel", WORD),
        ("wProcessorRevision", WORD),
]

class MEMORY_BASIC_INFORMATION(Structure):
    """
    MEMORY_BASIC_INFORMATION contains information about a 
    particular region of memory. A call to kernel32.VirtualQuery()
    populates this structure
    """
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
]
    
class IMAGE_SECTION_HEADER(Structure):
    """
    IMAGE_SECTION_HEADER contains information about a section defined in the 
    PE header of a executable file. 
    """
    _fields_ = [
        ("Name1", DWORD),
        ("Name2", DWORD),
        ("VirtualSize", DWORD),
        ("VirtualAddress", DWORD),
        ("SizeOfRawData", DWORD),
        ("PointerToRawData", DWORD),
        ("PointerToRelocations", DWORD),
        ("PointerToLinenumbers", DWORD),
        ("NumberOfRelocations", WORD),
        ("NumberOfLinenumbers", WORD),
        ("Characteristics", DWORD),
]    
    def getSectionName(self):
        name = "\""
        name += struct.pack("I", self.Name1)
        name += struct.pack("I", self.Name2)
        name += "\""
        return name
    
