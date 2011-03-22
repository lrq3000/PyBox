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
#   script for starting a remote process
#   and also injecting PyBox into it
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

"""starter / injector """
import injector_defines
import processrigger

from ctypes import sizeof, byref, c_int, c_ulong, wintypes
import ctypes
import getopt
import os
import sys
import struct

KERNEL_32 = ctypes.windll.kernel32
ADVAPI_32 = ctypes.windll.advapi32
    
def start_process(exe_path, arguments, start_suspended=False):
    """ start a target process 
    @param exe_path: path to target executable 
    @type exe_path: string
    @param start_suspended: if set to True, process is started with 
                            *suspended* flag (optional) 
    @type start_suspended: bool                     
    @return: (process_id, main_thread_id) if creation was successful, 
              (-1, -1) otherwise
    """
    startupinfo = injector_defines.STARTUPINFO()
    startupinfo.cb = sizeof(startupinfo)
    process_information = injector_defines.PROCESS_INFORMATION()
    creation_flags = injector_defines.CREATE_NEW_CONSOLE
    
    if start_suspended:
        creation_flags += injector_defines.CREATE_SUSPENDED
        
    if not KERNEL_32.CreateProcessA(exe_path,
                               arguments,
                               None,
                               None,
                               None,
                               creation_flags,
                               None,
                               None,
                               byref(startupinfo),
                               byref(process_information)):
        print "ERROR: kernel32.CreateProcessA(%s) failed." % (exe_path)
        return (-1, -1)
    pid = process_information.dwProcessId 
    h_main_thread = process_information.hThread
    print "Process with PID %d (0x%08x) launched, main thread has TID: %d." % \
    (pid, pid, h_main_thread)
    
    return (pid, h_main_thread)



def inject_module_into_process(dll_path,
                               pid,
                               resume_main_thread=False,                               
                               h_main_thread=-1,
                               delay=2000,
                               pybox_starter_path = None,
                               python_path = None):
    """ start a target process 
    @param dll_path: path to module to inject (pybox.dll)
    @type dll_path: string
    @param pid: process id to inject into
    @type pid: int
    @param resume_main_thread: set this to True if a main thread
                               shall be resumed
    @type resume_main_thread: bool
    @param h_main_thread: thread id of main thread
    @type h_main_thread: int 
    @param delay: milliseconds delay after which thread is resumed
    @type delay: int
    @param pybox_starter_path: Path to the script that is to be executed after
                                injected pybox.dll (started from within there).
                                If this parameter is c{None} then a copy of the
                                current environment variable is used
    @type pybox_starter_path: string    
    @param python_path: Set the PYTHONPATH environment variable according to
                         this value. If c{None} then a copy of the current
                         environment variable is used.
    @type python_path: string

    @return: True on success, False otherwise
    """
    
    if not processrigger.grant_debug_privilege(pid):
        print >> sys.stderr, "Cannot set debug privileges for process (pid) %i"\
              % pid

    #### set environment variables according to setup #####
    # get default values if nothing given
    if pybox_starter_path == None:
        pybox_starter_path = os.getenv("PYBOX_FILE")
    if python_path == None:
        python_path = os.getenv("PYTHONPATH")

    if not processrigger.set_remote_env_var(pid,
                                            "PYBOX_FILE",
                                            pybox_starter_path):
        print >> sys.stderr, "Failed to set PYBOX_FILE environment variable "\
              " in process (PID) %i" % pid
        return False

    if python_path:
        if not processrigger.set_remote_env_var(pid,
                                                "PYTHONPATH",
                                                python_path):
            print >> sys.stderr, "Failed to set PYTHONPATH environment " \
                  "variable in process (PID) %i" % pid
            return False


    # obtain a handle for the target process and prepare the argument to 
    # LoadLibrary
    h_process = KERNEL_32.OpenProcess(injector_defines.PROCESS_ALL_ACCESS, \
                            False, int(pid))
    if not h_process:
        print >> sys.stderr, "Cannot access process (PID): %s" % pid
        return False
    
    virtual_mem = (injector_defines.MEM_COMMIT | injector_defines.MEM_RESERVE)
    arg_base_address = KERNEL_32.VirtualAllocEx(h_process, 0, len(dll_path), \
                           virtual_mem, injector_defines.PAGE_READWRITE)
    
    bytes_written = c_int(0)
    if not KERNEL_32.WriteProcessMemory(h_process, arg_base_address, dll_path, \
                                        len(dll_path), byref(bytes_written)):
        print >> sys.stderr, "ERROR: Failed to write in remote process"
        return False

    # identify position of LoadLibraryA under the assumption that
    # kernel32.dll is loaded at the same memory position in the target process
    h_kernel_32 = KERNEL_32.GetModuleHandleA("kernel32.dll")
    h_load_library  = KERNEL_32.GetProcAddress(h_kernel_32,"LoadLibraryA")
    
    new_thread_id = c_ulong(0)
    
    if not KERNEL_32.CreateRemoteThread(h_process,
                           None,
                           0,
                           h_load_library,
                           arg_base_address,
                           0,
                           byref(new_thread_id)):
        print >> sys.stderr, "ERROR: Injection failed"
        return False
    
    print "Successfully created remote thread with thread ID " \
          "of: %d (0x%08x)" % (new_thread_id.value, new_thread_id.value)

    if resume_main_thread and h_main_thread > -1 and delay > -1:
        #print "Sleeping for %02.2f seconds" % (delay/1000)
        KERNEL_32.Sleep(delay)
        if not KERNEL_32.ResumeThread(h_main_thread):
            print >> sys.stderr, "ERROR: Failed to resume main thread."
            return False
        #print "Main thread successfully resumed."
    return True


def usage():
    """ print usage of this script """

    print """
************************
* PyBox injector usage *
************************
list of options:\n
-h --help
    print this help
-e <string> --executable=<string>
    Path to executable to be started
-m <string> --module=<string>
    Path to module to injected
-p <int> --pid=<int>
    Process ID to inject into
-s --suspended <delay>
    Start process suspended, inject, and start after <delay> milliseconds.\n
Example:
    %s --executable C:\Windows\system32\calc.exe --module PYTHONPATH/DLL/PyBox.dll""" % sys.argv[0]

    sys.exit(0)

def main(argv):
    """Main method that starts a target process and injects the native PyBox 
    module
    """
    
    exe_path = None
    pid = -1
    tid = -1
    start_suspended = False
    dll_path = None
    already_started = False
    arguments = ""
    delay = 0
    
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h:e:a:p:s:m:", ["help", \
                                   "executable=", "args=", "pid=", \
                                   "suspended=", "module="])
    except getopt.GetoptError, err:
        print str(err)
        usage()
        return 1

    if len(opts) == 0:
        usage()
        return 1
        
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(1)
        elif opt in ("-e", "--executable"):
            exe_path = arg
        elif opt in ("-a", "--args"):
            arguments = arg
        elif opt in ("-p", "--pid"):
            try:
                pid = int(arg)
            except ValueError:
                print >> sys.stderr, "Process ID (pid) must be numeric " \
                    " (decimal)"
                sys.exit(1)
        elif opt in ("-s", "--suspended"):
            start_suspended = True
            try:
                delay = int(arg)
            except ValueError:
                print >> sys.stderr, "suspended delay must be numeric"
                sys.exit(1)            
        elif opt in ("-m", "--module"):
            dll_path = arg
        else:
            assert False, "unhandled option"

    # -- error handling --
    if exe_path and (pid > -1):
        print >> sys.stderr, "Cannot execute AND inject into other process. " \
            "Please use either -e or -p."
        return 2

    if (not exe_path) and (pid < 0):
        print >> sys.stderr, "Either executable to start or process to inject" \
        "to must be given. Please use either -e or -p."
        return 2
        
    if not dll_path:
        print >> sys.stderr, "Module path is required. Please set -m"
        return 2

    dll_path = os.path.abspath(dll_path)

    if not os.path.exists(dll_path):
        print >> sys.stderr, \
              "Module does not exit with the given path: %s" % dll_path
        return 2

    pybox_mod_path = os.getenv("PYBOX_FILE")
    if not os.path.exists(pybox_mod_path):
        print >> sys.stderr, \
            "PYBOX_FILE does not exit with the given path: %s" % pybox_mod_path
        return 2

        


    # -- do stuff :) --

    result = True
    if exe_path is not None:
        (pid, tid) = start_process(exe_path, arguments, start_suspended)
        already_started = True
    if pid > -1 and dll_path is not None:
        if already_started:
            print "... using process id of created process (%d)" % pid
            if start_suspended:
                result = inject_module_into_process(dll_path,
                                                    pid,
                                                    True,
                                                    tid,
                                                    delay=delay)
            else:
                result = inject_module_into_process(dll_path, pid)
        else: 
            print "... using process id from argument pid (%d)" % pid
            result = inject_module_into_process(dll_path, pid)

    if not result:
        print >> sys.stderr, \
              "Failed into inject '%s' into process (ID) %i" % \
              (dll_path, pid)
        return 3


    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
    
