GOTO EndComment
########################################################################
# Copyright (c) 2010
# Felix S. Leder <leder<at>cs<dot>uni-bonn<dot>de>
# Daniel Plohmann <plohmann<at>cs<dot>uni-bonn<dot>de>
# All rights reserved.
########################################################################
# Description:
#   Example of a batch file for starting a new process for analysis
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
:EndComment

set PYTHON=C:\Python26
set PYTHONPATH=C:\PyBox\trunk
set PYBOX_FILE=.\starter.py
set PYBOX_LOG=C:\PyBox\log
%PYTHON%\python.exe %PYTHONPATH%\src\injector.py --executable "%WINDIR%\system32\notepad.exe" --module %PYTHONPATH%\DLL\PyBox.dll
