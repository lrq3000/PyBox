# PyBox
Mirror of PyBox from code.google.com/p/pyboxed, a user-level framework for monitoring processes. PyBox consists of

- a module (PyBox.dll), which is being injected into a target process and
- an API providing various tools for logging and analysis of activity as well as full manipulation of processes.

This rootkit-like approach allows close monitoring of behavior, thus helping to understand functionality of programs.

What is PyBox
---------------
PyBox (short for "Python Sandbox") is a flexible and light-weight process and system analysis framework.

Originally, we started this project with the intention to create a sandbox toolkit for semi-automated malware analysis, which is both easy to understand and extend. Using Python as main programming language allows dynamic and even runtime modifications to the scripts containing monitoring settings and functionality. This removes the need for frequent re-compilation of source code when tailoring the application to special cases and benefits the idea of rapid prototyping.

The original idea of PyBox is described in

PyBox - A Python approach to sandboxing. Felix Leder and Daniel Plohmann, 2010. https://eldorado.tu-dortmund.de/bitstream/2003/27336/1/BookOfAbstracts_Spring5_2010.pdf

Requirements and Setup
----------------------

### Requirements

The only requirement for using PyBox is a working installation of Python 2.6 or above (limited to Python 2.x) and a good portion of creativity. :)

### Setup

In the following, some general information for setting up PyBox is given. Please read and accept the notice given in the next paragraph. When using PyBox, we suspect that you know what you are doing.

### Important Notice

PyBox can be used for massive manipulations that can reach down to system processes. This can affect the stability of a system significantly. The PyBox framework should therefore not be used on a productive system that is used and required in daily activities. Best use is made on a dedicated analysis system or in a Virtual Machine.

### Files

The PyBox framework is ready to run out of the box.

Current directory structure and short description of the files of which PyBox consists:

- /DLL
- /DLL/PyBox.dll
- /DLL/PyBox.cpp
  * "PyBox.dll" is the readily compiled module, which is being injected to a target process and serves as a platform for the activies of PyBox.
- /src
- /src/starter.py
  * generic example script of a starter file.
- /src/injector.py
- /src/injector_defines.py
  * this script is used to inject a module (for the usage of PyBox, the above introduced PyBox.dll) into a target process. The injector can either start a new process (Path to executable given by parameter -e) or use an already existing process (identified by PID with parameter -p) as target.
- /src/processrigger.py
  * provides functionality for the manipulation of processes, for example setting the SE_Debug token or calling arbitrary API functions remotely (experimental!)
- /src/pydasm.pyd_2.6.5
- /src/pydasm.license
  * pydasm is the python part of the excellent free disassembler libdasm and used by PyBox in the course of installing hooks.
- /src/pybox
- /src/pybox/init.py
- /src/pybox/defines.py
- /src/pybox/emodules.py
- /src/pybox/hooking.py
- /src/pybox/memorymanager.py
  * core files of PyBox.
- /src/pybox/proctrack
- /src/pybox/proctrack/init.py
  * module for tracing behaviour of processes in terms of process creation. If it is noticed that a new process is spawned by the monitored process or a new remote thread is started, this module will inject a PyBox into the new process / hosting process for the new remote thread.
- /src/boxes/stdbox
- /src/boxes/stdbox/example_notepad.bat
- /src/boxes/stdbox/starter.py
- /src/boxes/stdbox/hooks_file.py
- /src/boxes/stdbox/hooks_memory.py
- /src/boxes/stdbox/hooks_misc.py
- /src/boxes/stdbox/hooks_network.py
- /src/boxes/stdbox/hooks_registry.py
- /src/boxes/stdbox/hooks_services.py
- /src/boxes/stdbox/hooks_synchronisation.py
  * example application of PyBox. Stdbox is a sandbox implementation based on PyBox for monitoring and logging a range of API calls in the target process.

### Environment Variables

- PYTHON: used by Python itself, points to the base installation directory of Python
- PYTHONPATH: used by PyBox, points to PyBox base directory (is set locally as example in stdbox/example_notepad.bat)
- PYBOX_FILE: used by PyBox, points to the Python starter file used for the desired run (is set locally as example in stdbox/example_notepad.bat)
- PYBOX_LOG: used by PyBox, points to the directory, in which log files will be generated (is set locally as example in stdbox/example_notepad.bat)
