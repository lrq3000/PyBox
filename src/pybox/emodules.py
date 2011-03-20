#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:       $Id: emodules.py 55 2011-03-08 15:10:34Z leder $
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
eModules contains all objects that enumerate and gather information about
executable modules (most often DLLs) that are mapped into the process
space of the process examined
"""

#standard python
import ctypes
import logging

from ctypes import byref, sizeof

#from pybox module
import defines

#native pybox module
import emb


KERNEL_32 = ctypes.windll.kernel32

class ModuleInfo(object):
    """Class contains the major information about a loaded module"""

    def __init__(self, name, start = 0, end = 0):
        self.module_name = name
        self.start_addr = start
        self.end_addr = end
        
        self.exported_functions = []
        self.address2function = {}
        self.function2address = {}

        self.update()

    def update(self):
        """Updates internal listing of currently loaded modules"""
        func_table = emb.dllEnumerateExportedFunctions(self.module_name)

        if len(func_table) == 1:
            logging.error("Failed to enumerate functions for module " + \
                          self.module_name)
            return

        func_addrs = func_table[0]
        func_names = func_table[1]        
        
        for i in xrange(len(func_addrs)):
            name = func_names[i]
            addr = func_addrs[i]

            #logging.debug("%s: %s - %08x" % (self.module_name, name, addr))
            
            self.exported_functions.append(name)
            self.address2function[addr] = name
            self.function2address[name] = addr

    def get_address(self, function_name):
        """tries to translate a function name to an address.
        @param function_name: name of a function
        @type function_name: string
        @return: address of the function or 0 if not found
        """
        if not self.function2address.has_key(function_name):
            return 0

        return self.function2address[function_name]


    def get_function(self, address):
        """tries to translate an address to a function name.
        @param address: memory address
        @type address: int
        @return: Name of the function or empty string if not found
        """
        if not self.address2function.has_key(address):
            return ""
        
        return self.address2function[address]


class ExecModulesInfo(object):
    """
    Contains a list of loaded modules and performs lookup of address
    and name mappings.
    """

    def __init__(self):
        self.loaded_modules = {}
        self.module_regions = {}

        self.__enumerate_modules()

    def __enumerate_modules(self):
        """internally enumerate all currently loaded modules
        """
        module_entry = defines.MODULEENTRY32()
        snapshot = KERNEL_32.CreateToolhelp32Snapshot(\
                                            defines.TH32CS_SNAPMODULE,\
                                            KERNEL_32.GetCurrentProcessId())
        if snapshot == None:
            logging.error("Cannot get snapshot for current Process")
            return False
        
        module_entry.dwSize = sizeof(module_entry)
        
        current = KERNEL_32.Module32First(snapshot, byref(module_entry))

        while current:
            name = module_entry.szModule.upper()
            if not self.loaded_modules.has_key(name):
                start = module_entry.modBaseAddr
                end = start + module_entry.modBaseSize

                #logging.debug("Module %s: %08x" % (name, start))
            
                self.loaded_modules[name] = ModuleInfo(name, start, end)                
                self.module_regions[name] = (start, end)

            current = KERNEL_32.Module32Next(snapshot, byref(module_entry))
            
        KERNEL_32.CloseHandle(snapshot)
        return True

    def update(self):
        """update internal list of all currently loaded modules
        """
        self.__enumerate_modules()

    def get_function_addrs(self, function_name, module_name = ""):
        """Get a list of all addresses for the given function name.
        @param function_name: Name of the function to look for
        @type function_name: str
        @param module_name: (optional) the module in which the function is
        @type module_name: str
        @return: list of all addresses that matched the given function name
                 (can be multiple if found in multiple modules)
        """
        result = []
        if (len(module_name) > 0):
            if not self.loaded_modules.has_key(module_name):
                mods = []
            else:
                mods = [self.loaded_modules[module_name]]
        else:
            mods = self.loaded_modules.values()
            
        for mod in mods:
            addr = mod.get_address(function_name)
            if addr > 0:
                result.append(addr)

        return result


    def get_module_name(self, address):
        """Return the name of the module at the given adress.
        @param address: Address within the module
        @type address: int
        @return: Module name or "" if not found
        """
        mods = [name for (name, (start, end)) in self.module_regions.items() \
                if start <= address <= end]

        if len(mods) == 1:
            return mods[0]
        elif len(mods) > 1:
            logging.error("DLLs are overlapping. Something is terribly wrong")

        return ""


    def get_module(self, address):
        """Returns the module object that contains this address
        @param address: Address within the module
        @type address: int
        @return: ModuleInfo object or None if not found
        """
        mods = [name for (name, (start, end)) in self.module_regions.items() \
                if start <= address <= end]

        if len(mods) == 1:
            name = mods[0]
            return self.loaded_modules[name]
        elif len(mods) > 1:
            logging.error("DLLs are overlapping. Something is terribly wrong")

        return None


    def get_function_name(self, address):
        """Return the name of the function I{starting} at the given address.
        If not function is starting at the given address an empty string is
        returned.
        @param address: Start address of the function
        @type address: int
        @return: Name of the function or empty string if not found
        """
        mod = self.get_module_name(address)
        if len(mod) == 0:
            return ""
        if not self.loaded_modules.has_key(mod):
            return ""
        
        return self.loaded_modules[mod].get_function(address)


## some information about the main module

def get_main_pid():
    """Returns the process id of the main executable"""

    return KERNEL_32.GetCurrentProcessId()

def get_main_path():
    """Returns the full path of the main executable"""

    MAX_PATH = 260 # according to MS :)

    buf = ctypes.create_string_buffer(MAX_PATH)

    if KERNEL_32.GetModuleFileNameA(0, buf, MAX_PATH) <= 0:
        return ""

    return buf.value
