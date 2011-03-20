#!/usr/bin/python
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Id:       $Id: starter.py 52 2011-02-24 21:42:51Z leder $
########################################################################
# Description:
#   Main module of pybox package
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


import logging
import pybox
import time

from pybox import proctrack

def register_hooks():
    """Register the required hooks"""

    logging.debug("Hooking")

def cleaner():
    logging.debug("cleaning up...")


if __name__ == "__main__":
    logging.basicConfig(format = "%(asctime)s - %(levelname)s - %(message)s",
                        level = logging.INFO)
    
    pybox.init()
    import emb
    emb.setCleanupFunction(cleaner)

    logging.info("Start")
    
    register_hooks()
    proctrack.init()
    
    logging.info("Let's get ready to rumble")
    time.sleep(2)
    logging.info("Done")
