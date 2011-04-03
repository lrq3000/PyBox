#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:       $Id: starter.py 38 2010-09-22 12:22:10Z leder $
########################################################################
# Description:
#   Main module for the standard sandbox
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

"""Main module to use PyBox. Everything is initialized from within here"""

import ctypes

import logging
import struct
import sys
import time

import pybox
import pybox.hooking
import pybox.memorymanager
import pybox.proctrack

import hooks_executable
import hooks_file
import hooks_memory
import hooks_misc
import hooks_network
import hooks_registry
import hooks_services
import hooks_synchronisation

cast = ctypes.cast
POINTER = ctypes.POINTER
c_uint = ctypes.c_uint

def register_hooks():
    """Register all hooks"""

    logging.debug("Hooking")
    hooks_executable.init()
    hooks_file.init()
    hooks_memory.init()
    hooks_misc.init()
    hooks_network.init()
    hooks_registry.init()
    hooks_services.init()
    hooks_synchronisation.init()
    
    return

def cleaner():
    logging.info("Cleaning up hooks...")

if __name__ == "__main__":
    logging.basicConfig(format = "%(asctime)s - %(levelname)s - %(message)s",
                        level = logging.INFO)
    
    pybox.init()
    pybox.proctrack.init()
    pybox.set_cleanup_function(cleaner)

    logging.info("Starting to monitor (pid: %i): %s" % \
                     (pybox.get_process_id(), pybox.get_process_path())
                 )

    
    logging.info("Start")
    
    pybox.set_global_lock(True)
    register_hooks()
    pybox.set_global_lock(False)
    
    logging.info("Let's get ready to rumble")

