//#include <Tlhelp32.h>
#include <stdio.h>
#include <windows.h>
#include <time.h>
#include <String.h>

#include <map>

// This is a Workaround for a problem caused by python.h in combination with VC++
#ifdef _DEBUG
#  undef _DEBUG
#  include "Python.h"
#  define DEBUG
#  define _DEBUG
#else
#  include "Python.h"
#endif



// End of Workaround

FILE *logFile = NULL;		// Pointer to logfile
static int debugMsgs = 0;
char *LOG_FILE_PATH = NULL;
char *PYBOX_FILE = NULL;
static PyObject *pythonCallbackHandler = NULL;
static PyObject *pythonCleanupCallback = NULL;
static int callbackLock = 0;
static int globalLock = 0; //lock for all threads

static HINSTANCE dll_handle = NULL;

/* MULTI THREADING between C and PYTHON IS BOGOUS 

   Threads accessing the Python interpreter must mutually exclusively hold
   the GIL (Global Interpreter Lock). Otherwise things like ojbect reference
   count and such can mess up.

   For this reason, only one thread can call the python callbacks at a time.
   THIS MAY LEAD TO INTERLOCKING when TWO THREADS TRY TO SYNCHRONIZE WITHIN
   THE PYTHON CALLBACKS
   */
#define USE_THREADS 1


#ifdef USE_THREADS
using namespace std;

typedef map<int, BOOLEAN> INT2BOOLMAP;
typedef pair<int, BOOLEAN> INT2BOOLPAIR;
INT2BOOLMAP lockmap;

CRITICAL_SECTION thread_lock_section;
CRITICAL_SECTION python_GIL_section;

#endif


void writeLog(char *msg) {
	char timestamp_buf[128];

	_snprintf_s(timestamp_buf, sizeof(timestamp_buf)-1, "%0.3fs PyBox.dll: ", (1.0 * clock() / CLOCKS_PER_SEC));
	OutputDebugStringA(timestamp_buf);
	OutputDebugStringA(msg);
	OutputDebugStringA("\n");	
}

void writeDebugMsg(char *msg) {
	if(debugMsgs) {
		writeLog(msg);
	}
}



static int getTID() {
	return GetCurrentThreadId();	
}


/********************* THE generic hook callback ********************/

/*
   genericCallback

   This function gets called from every installed hook.
   It makes sure that it is not called recursively (should be thread-safe ;) )
   and calls the generic python callback if it has been registered using
   "dllAttachPythonCallback"
*/

void __stdcall genericCallback(unsigned int originAddr, unsigned int check_lock) {
	
#ifdef USE_THREADS
	DWORD tid = GetCurrentThreadId();
	INT2BOOLMAP::iterator lm_iter;

	if (globalLock)
		return;  //stop if global lock is set

	if (check_lock) {	

		EnterCriticalSection(&thread_lock_section);
				
		lm_iter = lockmap.find(tid);
		if (lm_iter == lockmap.end()){
			INT2BOOLPAIR new_elem = INT2BOOLPAIR( tid, FALSE);
			lm_iter = lockmap.insert(new_elem).first;
		}

		if ((lm_iter == lockmap.end()) || ( (*lm_iter).second == TRUE) ) {
			LeaveCriticalSection(&thread_lock_section);
			return;
		}
		(*lm_iter).second = TRUE;

		LeaveCriticalSection(&thread_lock_section);
	}
#else
	if (check_lock) {
		if(callbackLock) {
			return;
		} else {
			callbackLock = 1;
		}	
	}
#endif

	//char msg[64];
	int ebpAddr = 0;
	int temp = 0;
	int stackOffset = 8;

#ifdef USE_THREADS
	EnterCriticalSection(&python_GIL_section);
	PyGILState_STATE state = PyGILState_Ensure();
#endif

	__asm {
		mov eax, ebp;
		mov ebpAddr, eax;
	}
    /*
	writeLog("###############################");
	sprintf_s(msg, 64, "Reporting callback.");
	writeLog(msg);
	sprintf_s(msg, 64, "hookedAddr: 0x%x - ebpAddr: 0x%x", originAddr, ebpAddr);
	writeLog(msg);	
	*/

    PyObject *argList = NULL;
    PyObject *result = NULL;

    // pass originAddr to callbackHandler
    argList = Py_BuildValue("II", originAddr,ebpAddr);
    result = PyEval_CallObject(pythonCallbackHandler, argList);
    Py_DECREF(argList);

	if (result == NULL) {
		writeLog("*** ERROR *** genericCallback: Python callback failed");
		PyErr_Print();

#ifdef USE_THREADS
		(*lm_iter).second = FALSE;
		PyGILState_Release(state);
		LeaveCriticalSection(&python_GIL_section);
#endif
        return; // Pass error back
	} else {	    
	}

	Py_DECREF(result);

#ifdef USE_THREADS
	PyGILState_Release(state);
	LeaveCriticalSection(&python_GIL_section);

	if (check_lock) {
		EnterCriticalSection(&thread_lock_section);
		(*lm_iter).second = FALSE;
		LeaveCriticalSection(&thread_lock_section);
	}
#else
	if (check_lock)
		callbackLock = 0;
#endif
	

	return;
}




/*************** Functions exported to Python by this module ********************/

/*
   pybox_attachPythonCallback

   Python-name: dllAttachPythonCallback

   attach a python callback function that gets called if our hook is called.
   The given parameter is a python function that will distribute the call
   to the corresponding python hook
*/
static PyObject *pybox_attachPythonCallback(PyObject *dummy, PyObject *args) {
	writeDebugMsg("emb.attachPythonCallback called");
    PyObject *result =  PyInt_FromLong(1);
    PyObject *temp = NULL;

    if (PyArg_ParseTuple(args, "O:set_callback", &temp)) {
        if (!PyCallable_Check(temp)) {
            PyErr_SetString(PyExc_TypeError, "parameter must be callable");
			writeLog("*** ERROR: parameter not callable");
			result = PyInt_FromLong(2);
            return NULL;
        }
        Py_XINCREF(temp);         /* Add a reference to new callback */
        Py_XDECREF(pythonCallbackHandler);  /* Dispose of previous callback */
        pythonCallbackHandler = temp;       /* Remember new callback */
        /* Boilerplate to return "None" */
        Py_INCREF(Py_None);
		result = PyInt_FromLong(0);
		writeDebugMsg("emb.attachPythonCallback: Python Callback Handler installed.");
    }
	writeDebugMsg("emb.attachPythonCallback left");
    return result;
}



/*  pybox_enumerateExportedFunctions

	Python-name: dllEnumerateExportedFunctions

    method to enumerate all functionNames + addresses for given module name 
	based on the export table of the module in PE header (from memory)
*/
static PyObject* pybox_enumerateExportedFunctions(PyObject *self, PyObject *args) {
	writeDebugMsg("emb.enumerateExportedFunctions called");
	char msg[128];
	char *dllName;
	if(!PyArg_ParseTuple(args, "s", &dllName)) {
   	     return NULL;
	}
	sprintf_s(msg, 128, "emb.enumerateExportedFunctions DLL to analyze %s", dllName);
	writeDebugMsg(msg);

	BYTE *hMod = (BYTE*)GetModuleHandleA(dllName);
	if(!hMod) {
		sprintf_s(msg, 128, "*** ERROR *** enumerateExportedFunctions: handle for [%s] is NULL!", dllName);
		writeLog(msg);
		PyObject *retAddresses = PyList_New(1);
		PyObject *addr = PyInt_FromLong(0);
		PyList_SET_ITEM(retAddresses, 0, addr);
		return retAddresses;
	}
	sprintf_s(msg, 128, "emb.enumerateExportedFunctions moduleHandle 0x%x\n", hMod);
	writeDebugMsg(msg);

	//parse export table
	IMAGE_NT_HEADERS *pnt = (IMAGE_NT_HEADERS*)&hMod[PIMAGE_DOS_HEADER(hMod)->e_lfanew];
	IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY*)&hMod[pnt->OptionalHeader.DataDirectory->VirtualAddress];
	DWORD *dwFunctions = (DWORD*)&hMod[exp->AddressOfNames];
	DWORD *dwFunctionAddresses = (DWORD*)&hMod[exp->AddressOfFunctions];
	WORD *dwOrdinals = (WORD*) &hMod[exp->AddressOfNameOrdinals];

	//FIXME: use instead of other two arrays
	PyObject *entries = PyList_New(exp->NumberOfFunctions);

	PyObject *retAddresses = PyList_New(0);
	PyObject *retNames = PyList_New(0);

	for (DWORD ctr = 0; ctr < exp->NumberOfFunctions; ctr++) {
		
		WORD index = dwOrdinals[ctr];
		WORD ordinal = index  + (WORD)exp->Base;
		PyObject *name;

		if (index >= exp->NumberOfFunctions) {
			continue; //invalid/empty entry
		}

		unsigned int convAddr = (unsigned int)&hMod[dwFunctionAddresses[index]];
		PyObject *addr = PyInt_FromLong(convAddr);


		if (ctr < exp->NumberOfNames) {
			name = PyString_FromString((char*)&hMod[dwFunctions[ctr]]);
		}
		else {
			name = PyString_FromFormat("Ordinal%i", ordinal);
		}

		if (!name) {
			sprintf_s(msg, 128, "Failed to create export name/ordinal for entry #%i", ctr);
			writeLog(msg);
			continue;
		}

		PyList_Append(retAddresses, addr);
		PyList_Append(retNames, name);

		//FIXME: replace above by
		PyObject *entry = Py_BuildValue("(Oii)", name, convAddr, ordinal);
	}
	PyObject *returnTable = PyList_New(2);
	PyList_SET_ITEM(returnTable, 0, retAddresses);
	PyList_SET_ITEM(returnTable, 1, retNames);
	writeDebugMsg("emb.enumerateExportedFunctions left");
	return returnTable;
}


/* 
   pybox_setCleanupFunction

   Python-name: setCleanupFunction

   sets the cleanup callback function. The cleanup function
   will be called before this dll is unloaded.
 */
static PyObject* pybox_setCleanupFunction(PyObject *self, PyObject *args) {
	writeDebugMsg("emb.setCleanupFunction called");
    PyObject *result =  PyInt_FromLong(1);
    PyObject *temp = NULL;

	Py_XDECREF(pythonCleanupCallback);

	if (PyArg_ParseTuple(args, "O", &pythonCleanupCallback)) {
		if (!PyCallable_Check(pythonCleanupCallback)) {
			pythonCleanupCallback = NULL;
            PyErr_SetString(PyExc_TypeError, "Parameter is not a callable function");
			writeLog("*** ERROR: parameter not callable");
            return NULL;
        }

		Py_XINCREF(pythonCleanupCallback);  /* Dispose of previous callback */
		result = PyInt_FromLong(0);
		writeDebugMsg("emb.setCleanupFunction: Python Cleanup installed.");
    }
	writeDebugMsg("emb.setCleanupFunction left");
    return result;
}


/* 
   pybox_getGenericCallbackAddress

   Python-name: dllGetGenericCallbackAddress

   returns the callback address from this DLL to python. Used
   when creating the actual hooks in memory.
 */
static PyObject* pybox_getGenericCallbackAddress(PyObject *self, PyObject *args) {
	writeDebugMsg("emb.getGenericCallbackAddress called");
	PyObject *returnObj = Py_BuildValue("I", &genericCallback);
	writeDebugMsg("emb.getGenericCallbackAddress left");
	return returnObj;
}

/*
   pybox_getProcessId

   Python-name: dllGetProcessId

   C wrapper for GetProcessId (not included in ctypes) 
*/
static PyObject* pybox_getProcessId(PyObject *self, PyObject *args) {
	writeDebugMsg("emb.getProcessId called");
	
	HANDLE process_handle;

	if(!PyArg_ParseTuple(args, "i", (int*)&process_handle)) {
   	     return NULL;
	}

	int pid = GetProcessId(process_handle);
	PyObject *returnObj = Py_BuildValue("I", pid);

	writeDebugMsg("emb.getProcessId left");
	return returnObj;
}


/*
	pybox_setGlobalLock

	Python-name: setGlobalLock

	C function for setting the global lock
*/
static PyObject* pybox_setGlobalLock(PyObject *self, PyObject *args) {
	writeDebugMsg("emb.setGlobalLock called");

	if(!PyArg_ParseTuple(args, "i", (int*)&globalLock)) {
   	     return NULL;
	}

	writeDebugMsg("emb.setGlobalLock left");
	return Py_None;
}



/*
   pybox_getSelfFilename

   Python-name: dllGetFilename

   Get the full path to this dll. Not easily possible
   with other means using python on windows
*/
static PyObject* pybox_getSelfFilename(PyObject *self, PyObject *args) {
	writeDebugMsg("emb.GetFilename called");

	char path[FILENAME_MAX];
	PyObject *result = NULL;

	if (! GetModuleFileNameA(dll_handle,
							 path,
							 sizeof(path)) )
		return Py_None;

	result = PyString_FromString(path);
	
	Py_XINCREF(result);

	writeDebugMsg("emb.getFilename left");
	return result;
}

/* 
   pybox_getPebAddress

   Python-name: dllGetPebAddress

   Returns the start address of Process Environment Block. Used
   for acquiring information about certain process attributes, including the
   image base address, useful e.g. for dumping.
 */
static PyObject* pybox_getPebAddress(PyObject *self, PyObject *args) {
	writeDebugMsg("emb.getPebAddress called");
	void *pPeb;
    __asm {
        mov EAX, FS:[0x30]
        mov [pPeb], EAX
    }			
	PyObject *returnObj = Py_BuildValue("I", pPeb);
	writeDebugMsg("emb.getPebAddress left");
	return returnObj;
}

/*
   pybox_terminate

   Python-name: terminate

   Terminates pybox from within a hook.
   This requires some special cleanup in order to
   be stable.
*/
static PyObject* pybox_terminate(PyObject *self, PyObject *args) {
	writeDebugMsg("Terminate PyBox");

	int exitcode;
	PyObject *result = NULL;
	PyObject *arglist = NULL;


	if(!PyArg_ParseTuple(args, "i", (int*)&exitcode)) {
   	     return NULL;
	}


	if (pythonCleanupCallback && PyCallable_Check(pythonCleanupCallback)) {
		arglist = Py_BuildValue("()");
		result = PyEval_CallObject(pythonCleanupCallback, arglist);
		Py_XDECREF(arglist);
		Py_XDECREF(result);
		Py_XDECREF(pythonCleanupCallback);
		pythonCleanupCallback = NULL;
	}
	
	Py_Exit(exitcode);

	OutputDebugStringA("Terminate done");
	return result;
}



/* returns the callback address from this DLL to python
 * 
 */
//fixme: remove
/*
static PyObject* pybox_mallocWrapper(PyObject *self, PyObject *args) {
	int numBytes;
	void *memAddr;
	writeDebugMsg("emb.mallocWrapper called");
	if(!PyArg_ParseTuple(args, "i", &numBytes)) {
   	     return NULL;
	}
	memAddr = (void*)malloc(numBytes);
	PyObject *returnObj = Py_BuildValue("i", &memAddr);
	writeDebugMsg("emb.mallocWrapper left");
	return returnObj;
}
*/


/* C example remote function for python script */
// todo: remove
static PyObject* pybox_sampleCall(PyObject *self, PyObject *args) {
	writeDebugMsg("emb.sampleCall called");
	char msg[32];
	PyObject *result = NULL;
	int int1;
	if(!PyArg_ParseTuple(args, "i", &int1)) {
   	     return NULL;
	}
	result = PyInt_FromLong(getTID());
	sprintf_s(msg, 32, "parsed: %d", int1);
	writeDebugMsg(msg);
	writeDebugMsg("emb.sampleCall left");
	return result;
}



static PyMethodDef embeddedMethods[] = { 
	{"dllAttachPythonCallback", pybox_attachPythonCallback, METH_VARARGS, "attach python callback handler to injected DLL."},
	{"dllEnumerateExportedFunctions", pybox_enumerateExportedFunctions, METH_VARARGS, "enumerate all exported functions for given module name"},
	{"dllGetGenericCallbackAddress", pybox_getGenericCallbackAddress, METH_VARARGS, "address of generic callback in injected DLL"},
	{"dllGetProcessId", pybox_getProcessId, METH_VARARGS, "wrapper for kernel32.GetProcessId (not included in ctypes)"},
	{"setCleanupFunction", pybox_setCleanupFunction, METH_VARARGS, "Registers a cleanup function that gets called before the interpreter terminates"},
	{"dllGetFilename", pybox_getSelfFilename, METH_VARARGS, "Returns the path of the dll itself (useful for injection of same dll into other processes)"},
	{"setGlobalLock", pybox_setGlobalLock, METH_VARARGS, "Set the global lock to True (don't monitor anything) or False (regular monitoring)"},
	{"dllGetPebAddress", pybox_getPebAddress, METH_VARARGS, "Aquire start address of Process Environment Block."},
	{"terminate", pybox_terminate, METH_VARARGS, "Terminate pybox from within a hook. Argument is the Python exit code."},
	{"example", pybox_sampleCall, METH_VARARGS, "example call"},
	{NULL, NULL, 0, NULL}
};


/************ DllMain - init and cleanup *************/

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {	

	PyObject *Py_logfile;

	//MessageBoxA(NULL, "IN", "Error", NULL);

	dll_handle = hinst;

	if (dwReason == DLL_PROCESS_ATTACH) {

		if (logFile==NULL) {

			LOG_FILE_PATH = (char*) malloc(MAX_PATH);
			if (!LOG_FILE_PATH) {
				MessageBoxA(NULL, "Memory allocation failed", "Error", MB_ICONERROR);
				return FALSE;
			}

			if (! GetEnvironmentVariableA("PYBOX_LOG", LOG_FILE_PATH, MAX_PATH -1 )){
				MessageBoxA(NULL, "Environment variable PYBOX_LOG not set!", "Error", MB_ICONERROR);
				free(LOG_FILE_PATH);
				return FALSE;
			}
		}

		if (PYBOX_FILE == NULL) {
			PYBOX_FILE = (char*) malloc(MAX_PATH);
			if (!PYBOX_FILE) {
				MessageBoxA(NULL, "Memory allocation failed", "Error", MB_ICONERROR);
				return FALSE;
			}

			if (! GetEnvironmentVariableA("PYBOX_FILE", PYBOX_FILE, MAX_PATH -1 )){
				MessageBoxA(NULL, "Environment variable PYBOX_FILE not set!", "Error", MB_ICONERROR);
				free(PYBOX_FILE);
				return FALSE;
			}
		}

		if (!Py_IsInitialized()) {		
			//MessageBoxA(NULL, "starting", "", NULL);
			Py_InitializeEx(0);
			if (!Py_IsInitialized())
			{
				MessageBoxA(NULL, "Failed to start Python interpreter", "Error", NULL);
				return FALSE;
			}	
#ifdef USE_THREADS
			PyEval_InitThreads();
#endif
			
		}

#ifdef USE_THREADS
		InitializeCriticalSection(&thread_lock_section);
		InitializeCriticalSection(&python_GIL_section);

		EnterCriticalSection(&python_GIL_section);
		PyThreadState *tstate = PyEval_SaveThread();
		PyGILState_STATE state = PyGILState_Ensure();
#endif
		char filename[64]; // filename from process id
		int proc_id = GetCurrentProcessId();
		sprintf_s(filename, 64, "%s%d_log.txt", LOG_FILE_PATH, proc_id);

		Py_logfile = PyFile_FromString(filename, "w");
		if ( !Py_logfile){
			MessageBoxA(NULL, "Unable to open logfile", "Error", NULL);
		}
		else {			
			logFile = PyFile_AsFile(Py_logfile);

			Py_INCREF(Py_logfile);
			PySys_SetObject("stderr", Py_logfile);			
			writeLog("Logging active");
		}
		
		Py_InitModule("emb", embeddedMethods);
		writeLog("embedded python module initialized.");
		PyObject* PyFileObject = PyFile_FromString(PYBOX_FILE, "r");
		if (PyFileObject == NULL) {
			writeLog("*** ERROR *** main: loading starter.py");					
		}
		else {			
			callbackLock = 1; //no callbacks while we start hooking
			writeLog("Running starter.py");
			if (PyRun_SimpleFile(PyFile_AsFile(PyFileObject), PYBOX_FILE) == -1){
				writeLog("Execution of starter.py failed");
			}
			else
			   writeLog("starter.py finished");
			writeLog("done");
			Py_DECREF(PyFileObject);
			callbackLock = 0; //ready to go
		}		


#ifdef USE_THREADS
		PyGILState_Release(state);
		LeaveCriticalSection(&python_GIL_section);
#endif	
	}
	if (dwReason == DLL_THREAD_ATTACH) {
		OutputDebugStringA("Thread attached\n");
	}    
	if (dwReason == DLL_THREAD_DETACH) {
		OutputDebugStringA("Thread detached\n");
	}
	if (dwReason == DLL_PROCESS_DETACH) {	
		OutputDebugStringA("Process detach");

		PyObject *result = NULL;
		PyObject *arglist = NULL;
		if (pythonCleanupCallback) {
#ifdef USE_THREADS
			EnterCriticalSection(&python_GIL_section);
			PyGILState_STATE state = PyGILState_Ensure();
#endif		
			if (PyCallable_Check(pythonCleanupCallback)) {
				arglist = Py_BuildValue("()");
				result = PyEval_CallObject(pythonCleanupCallback, arglist);
				Py_XDECREF(arglist);
				Py_XDECREF(result);
			}
#ifdef USE_THREADS
			PyGILState_Release(state);
			LeaveCriticalSection(&python_GIL_section);			
#endif	
		}
		OutputDebugStringA("PyBox: All done");
	}
	return TRUE;
}

