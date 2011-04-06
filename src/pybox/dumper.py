#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:       $Id $
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
Dumper provides basic functionality required for the creation of process memory 
dumps. 
"""

#standard python
import logging
import sys
import os
from ctypes import sizeof, addressof, memmove

#pybox includes
import pybox
import pybox.memorymanager
import defines

def dump_pe_image():
    """
    Dumps the loaded PE image from memory. Target file is "dump_pe_image.bin" 
    located in the same folder that is used for logging, defined via 
    environment variable PYBOX_LOG.
    
    Information about specifications of the PE file format, including headers, 
    offsets used, and further detailed descriptions can be obtained from
    "Microsoft Portable Executable and Common Object File Format Specification", 
    Microsoft Corporation, Revision 6.0 - February 1999
    """
    
    logging.info("Starting the dumping of PE memory image.")
    # get image base from Process Environment Block
    image_base_addr = pybox.memorymanager.read_dword_from_addr(\
                                        pybox.get_peb_address() + 0x08)
    start_pe_header = image_base_addr + \
    pybox.memorymanager.read_word_from_addr(image_base_addr + 0x3c)
    num_sections = pybox.memorymanager.read_word_from_addr(start_pe_header + \
                                        0x06)
    start_opt_header = start_pe_header + 0x18
    size_opt_header = pybox.memorymanager.read_word_from_addr(\
                                        start_pe_header + 0x14)
    
    start_sections = start_opt_header + size_opt_header
    dump_file_name = os.getenv("PYBOX_LOG") + "dump_pe_image.bin"
    dump_file = open(dump_file_name, "wb")
    if not dump_file:
        print >> sys.stderr, "Failed to open file: \"%s\" for " \
            "dumping." % dump_file_name
        return False
    
    logging.info("Base address of PE image: 0x%08x", image_base_addr)
    logging.info("number of sections identified in header: " \
                 "0x%08x", num_sections)
    logging.info("Dumping to target file: %s", dump_file_name)
    
    pe_header_finished = False
    # iterate sections and dump then one-by-one
    # if PE header has not been build, start with the header
    for i in xrange(num_sections):
        section_header = defines.IMAGE_SECTION_HEADER()
        memmove(addressof(section_header), pybox.memorymanager.read_addr(start_sections+i*40, 40), sizeof(section_header))
        # find first non-zero section offset (PointerToRawData)
        # some packers (e.g. UPX) insert a dummy section
        if section_header.PointerToRawData > 0:
            if not pe_header_finished:
                logging.info("Building PE header...")
                # Size of whole PE header is determined by the pointer to 
                # the next section.
                size_pe_header = section_header.PointerToRawData
                header = pybox.memorymanager.read_addr(image_base_addr, size_pe_header)
                dump_file.write(header)
                pe_header_finished = True
            logging.info("Dumping memory of section: %s", section_header.getSectionName())
            # append current section to the dumped PE image
            section_memory = pybox.memorymanager.read_addr(image_base_addr + \
                                    section_header.VirtualAddress, section_header.SizeOfRawData)
            dump_file.write(section_memory)

    dump_file.close()
    logging.info("Dumping done!")
    
    return


def dump_full():
    """
    Dumps all regions from user space memory, including PE memory image. Target 
    file is "dump_full.bin" located in the defined via environment variable 
    PYBOX_LOG.
    """
    
    addr = 0
    dump_file_name = os.getenv("PYBOX_LOG") + "dump_full.bin"
    dump_file = open(dump_file_name, "wb")
    if not dump_file:
        print >> sys.stderr, "Failed to open file: \"%s\" for " \
            "dumping full memory image." % dump_file_name
        return False
       
    while addr < 0x80000000:
        region_info = pybox.memorymanager.get_region_information(addr)
        if not region_info:
            addr += 0x1000
            continue

        (start, size) = region_info
        if not pybox.MODULES.get_module_name(addr).endswith(".DLL"):
            (start, end) = (start, start + size)
            logging.info("trying to dump memory region beginning at 0x%08x " \
                         "with size 0x%08x.", start, size)
            
            # dump memory region to file
            mem = pybox.memorymanager.read_addr(start, size)
            dump_file.write(mem)
        addr = start+size
    dump_file.close()
            
    return