#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:       $Id: memorymanager.py 61 2011-03-15 12:51:45Z leder $
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
MemoryManager is responsible for "safe" memory accesses to the process' address
space. Rights will be set accordingly if not set correctly. Non-existent pages 
give zero return bytes.
"""

#FIXME: group functions by functionality

#standard python
import ctypes
import logging
import re
import struct

from ctypes import sizeof, byref, c_ulong

#from pybox module
import defines

KERNEL_32 = ctypes.windll.kernel32


def read_addr(address, num_bytes):
    """read a number of bytes from a given memory address. The function
    will try to override existing access rights to read from 
    the specified memory location anyway.
    @param address: address to read from
    @type address: int
    @param num_bytes: Number of bytes to read from that address
    @type num_bytes: int
    @return: bytes read
    """
    
    mbi = defines.MEMORY_BASIC_INFORMATION()
    if KERNEL_32.VirtualQuery(address,
                             byref(mbi),
                             sizeof(mbi)) != sizeof(mbi):
        logging.warning("[read_addr] could not read from given address")
        return ""

    if (mbi.State != defines.MEM_COMMIT):
        logging.warning("[read_addr] Memory: State != MEM_COMMIT for addr " \
                        "0x%08x (is 0x%08x)!", address, mbi.State)
        return ""
    
    elif (mbi.Protect & 0x100) == 0x100:
        logging.warning("[read_addr] Trying to access a guard page at " \
                        "address 0x%08x. Skipping memory operation", address)
        return ""

    elif (mbi.Protect & 0xe6) == 0:
        mem = read_protected_addr(mbi, address, num_bytes)
        return mem
    
    
    else:
        mem_buffer = ctypes.create_string_buffer(num_bytes)
        mem_buffer_addr = ctypes.addressof(mem_buffer)
        ctypes.memmove(mem_buffer_addr, address, num_bytes)
        return mem_buffer.raw


def read_protected_addr(mbi, address, num_bytes):
    """read a number of bytes from a given protected memory address. The access
    flags will be changed temporarily and then be restored afterwards.
    @param mbi: Memory basic information, obtained by read_addr
    @type mbi: MEMORY_BASIC_INFORMATION
    @param address: address to read from
    @type address: int
    @param num_bytes: Number of bytes to read from that address
    @type num_bytes: int
    @return: bytes read
    """
    mbi = defines.MEMORY_BASIC_INFORMATION()
    KERNEL_32.VirtualQuery(address,
                             byref(mbi),
                             sizeof(mbi))
    base = mbi.BaseAddress
    size = mbi.RegionSize
    old_protect = mbi.Protect
    new_protect = defines.PAGE_EXECUTE_READWRITE
    old_protect_dummy = defines.DWORD(0)

    logging.warning("[read_addr] Memory: Protection override!")
    KERNEL_32.VirtualProtect(base,
                            size,
                            new_protect,
                            byref(old_protect_dummy))
    mem_buffer = ctypes.create_string_buffer(num_bytes)
    ctypes.memmove(ctypes.addressof(mem_buffer), address, num_bytes)
    KERNEL_32.VirtualProtect(base,
                            size,
                            old_protect,
                            byref(old_protect_dummy))
    return mem_buffer.raw


def write_mem(address, data):
    """Write data to address. Data is either written completely, no error
    occurs on any of the bytes or not written at all.
    @param address: Memory address to write data to
    @type address: int
    @param data: data to write
    @type data: str
    @return: C{True} on success, C{False} on failure
    """

    data_len = len(data)

    #FIXME: memmove throws exception - no need to check using virtualquery
    #       speeds up but may throw exception in program
    #       -> other exception handler?
    chk_addr = address
    chk_len = data_len        
    while chk_len > 0:
        mbi = defines.MEMORY_BASIC_INFORMATION()
        if KERNEL_32.VirtualQuery(address,
                                 byref(mbi),
                                 sizeof(mbi)) != sizeof(mbi):
            logging.debug("VirtualQuery: Failed to get memory info")
            return False

        if (mbi.State != defines.MEM_COMMIT):
            logging.error("Cannot write to %x - protected with flags %x" % \
                          (address, mbi.Protect))
            return False
        if  mbi.Protect & 0xcc == 0:
            #logging.warn("Writing to address 0x%08x not allowed - using " \
            #             "aggressive writing" \
            #             % address)
            return write_mem_aggressive(address, data)


        bytes_in_page = (mbi.BaseAddress + mbi.RegionSize) - chk_addr
        chk_len -= bytes_in_page
        chk_addr += bytes_in_page

    # all data can be written to writeable pages - fine :)

    temp_buf = ctypes.create_string_buffer(data, len(data))
    ctypes.memmove(address, temp_buf, len(data))

    return True


def read_dword_from_addr(address):
    """read a dword (4 bytes) from a given memory address. The function 
    indirectly uses read_addr()
    @param address: address to read from
    @type address: int
    @return: dword read
    """
    mem_buffer = read_addr(address, 4)
    if len(mem_buffer) == 4:
        return struct.unpack("I", mem_buffer)[0]

    return 0

def read_word_from_addr(address):
    """read a dword (4 bytes) from a given memory address. The function 
    indirectly uses read_addr()
    @param address: address to read from
    @type address: int
    @return: dword read
    """
    mem_buffer = read_addr(address, 2)
    if len(mem_buffer) == 2:
        return struct.unpack("h", mem_buffer)[0]

    return 0


def read_dword_from_pointer(address):
    """read a dword (4 bytes) from a given pointer to a memory address. 
    The function indirectly uses read_addr()
    @param address: address where the pointer resides
    @type address: int
    @return: dword read
    """
    mem_buffer = read_addr(address, 4)
    if len(mem_buffer) == 4:
        pointer = struct.unpack("I", mem_buffer)[0]
        return read_dword_from_addr(pointer)

    return 0


def read_ascii_from_addr(address, size = None):
    """read an ascii string from a given pointer to a memory address. 
    The function indirectly uses read_addr()
    @param address: address where the pointer resides
    @type address: int
    @return: ascii string read
    """

    if not address:
        return ""

    if size == None:
        return ctypes.string_at(address)
    return ctypes.string_at(address, size)
        

def read_unicode_from_addr(address, size = None):
    """read an unicode string from a given pointer to a memory address. 
    The function indirectly uses read_addr()
    @param address: address where the pointer resides
    @type address: int
    @return: unicode string read
    """

    if not address:
        return unicode("")

    if size == None:
        return ctypes.wstring_at(address)
    return ctypes.wstring_at(address, size)


def get_current_process_handle():
    """get a process handle with all access for the current process
    @return: process handle
    """
    pid = KERNEL_32.GetCurrentProcessId()
    current_process = KERNEL_32.OpenProcess(defines.PROCESS_ALL_ACCESS,
                                          False,
                                          pid)
    if current_process == 0:
        logging.warning("Cannot get current process handle")
    return current_process #may return 0


def set_executable(address, size):
    """set executable flag for a subsequent number of bytes beginning at
    given address.
    @param address: address of first byte to set executable
    @type address: int
    @param size: number of bytes to set executable
    @type size: int
    """
    mbi = defines.MEMORY_BASIC_INFORMATION()
    if KERNEL_32.VirtualQuery(address,
                             byref(mbi),
                             sizeof(mbi)) != sizeof(mbi):
        logging.error("VirtualQuery: Failed to get memory info")
        return False

    if mbi.Protect >= 0x10:
        return True #already executable

    new_protect = mbi.Protect << 4 # add EXEC
    old_protect = defines.DWORD(0)
    if not KERNEL_32.VirtualProtect(address,
                                   size,
                                   new_protect,
                                   byref(old_protect)):
        logging.error("Cannot set address 0x%08x to executable" %\
                      address)
        return False

    return True


def write_mem_aggressive(address, data):
    """Write data into process using WriteProcessMemory, which overrides
    the default memory page settings.
    @param address: Memory address to write data to
    @type address: int
    @param data: data to write
    @type data: str
    @return: C{True} on success, C{False} on failure
    """

    process = get_current_process_handle()
    if process == 0:
        return False

    data_len = len(data)

    temp_buf = ctypes.create_string_buffer(data, data_len)
    written = c_ulong(0)

    result = KERNEL_32.WriteProcessMemory(process,
                                         address,
                                         temp_buf,
                                         data_len,
                                         byref(written))
    KERNEL_32.CloseHandle(process)

    if not result:
        logging.error("WriteProcessMemory failed: 0x%x" % \
                      KERNEL_32.GetLastError())
        return False
    if written.value != data_len:
        logging.warn("WriteProcessMemory: only %i bytes written to 0x%x" % \
                     (written.value, address))
        return False

    return True


def find(start_addr, end_addr, pattern):
    """Search for all occurences of pattern betwen start address and end address
    @param start_addr: start address to start to search from
    @type start_addr: int
    @param end_addr: end address to stop searching at
    @type end_addr: int
    @param pattern: search pattern (needle)
    @type pattern: str
    @return: list of addresses at which the pattern is found
    """
    find_positions = []
    
    position = start_addr
    #logging.info("start, end: %x, %x" % (start, end))
    
    while (position) and (end_addr - position > 4):        
        bufptr = ctypes.cast(position, ctypes.POINTER(ctypes.c_char))
        fpos = bufptr[0:end_addr-position].find(pattern)
        
        if fpos < 0:
            break
        
        position += fpos
        if position:
            find_positions.append( position )
        position += 1

    return find_positions


def find_regex(start_addr, end_addr, regex_pattern):
    """Search for all occurences of the regular expression (pattern) betwen
       start address and end address
    @param start_addr: start address to start to search from
    @type start_addr: int
    @param end_addr: end address to stop searching at
    @type end_addr: int
    @param pattern: regular expression to search for (needle)
    @type pattern: str
    @return: list of addresses at which the pattern is found
    """
    bufptr = ctypes.cast(start_addr, ctypes.POINTER(ctypes.c_char))
    fpositions = re.finditer(regex_pattern, bufptr[0:end_addr-start_addr])

    result = []
    if not fpositions:
        return result

    for pos in fpositions:
        result.append(start_addr + pos.start())

    return result


def get_region_information(address):
    """Return start and size of the region in which the address belongs. This
    consists of a range of pages that are commited together.
    @param address: Memory address to get the region for
    @type address: int
    @return: tuple consisting of (start, size) of region or C{None} if address
    not committed
    """
    mbi = defines.MEMORY_BASIC_INFORMATION()
    if ctypes.windll.kernel32.VirtualQuery(address,
                                           byref(mbi),
                                           sizeof(mbi)) != sizeof(mbi):
        return None

    if not (mbi.State & defines.MEM_COMMIT):
        return None

    return (mbi.BaseAddress, mbi.RegionSize)


