#define MM_CRTDBG_CPP
#include "mm_CrtDbg.h"
#if defined(_CRTDBG__NO_MICROSOFT)
/***************************************************************************
 * CFCU ("cheap for commercial use") LICENSE NOTE!                         *
 ***************************************************************************
 * ANY USE OF THIS FILE REQUIRES TO ACCEPT THE ATTACHED LICENSE AGREEMENT. *
 * BY USING THIS FILE, YOU AUTOMATICALLY (IMPLICIT) ACCCEPT THE AGREEMENT. *
 * FOR THE LICENSE AGREEMENT IN DETAIL, SEE THE COMPANION FILES.           *
 * (c) 2012-April-16 Maik Reiss, Germany.                                  *
 * <mailto:modem-man@gmx.net?subject=_CrtDbg%20for%20WinCE>                *
 ***************************************************************************/


/**** in development switches, only for the author *************************/
#define IGNOREABLES_INTERNALS 0  // since some internal used ressources (memory) are still open, we would see our own as a "leak", so future release will uncount itself
/***************************************************************************/
/* === add winsock 2 library BEFORE windows.h === */
#if !defined( CRTDBG_NO_WS ) && !defined( CRTDBG_WS1 )
#  include <winsock2.h> // I also like to boundcheck winsock
#elif !defined( CRTDBG_NO_WS ) && defined( CRTDBG_WS1 )
#  include <winsock.h>
#endif //!defined( CRTDBG_NO_WS ) && !defined( CRTDBG_WS1 )

#if !defined( CRTDBG_NO_WS )
#  if defined (_WIN32_WCE) /* WinCE / PPC etc. must link ws2.lib */
#    pragma comment( lib, "ws2.lib" )
#  else   /* Desktop Windows (NT4, W2K, XP etc. must link ws2.lib */
#    pragma comment( lib, "ws2_32.lib" )
#  endif
#endif //!defined( CRTDBG_NO_WS )

#if defined(_CRT_DEBUGBREAK) // if defined we can control how much Breakpoints will be fired right in the problem position 
#  if (_CRT_DEBUGBREAK==0)   // if defined and ==0 we will get more silence, program is nearly seamless running until Report/Dump, even in DEBUG build
#  define _MM_DebugBreak() do{;}while(0)
#  elif (_CRT_DEBUGBREAK==1) // if defined and ==1 we will get the old behaviour (much Breakpoints/Assertions in DEBUG Builds), 
#  define _MM_DebugBreak() DebugBreak();
#  else
#  endif
#else // if not defined, we will only get BreakPoints in CrtDbgReport() and CrtDumpMemoryLeaks()
#  define _MM_DebugBreak() do{;}while(0)
#endif

#include <windows.h> // whole winapi must be known
#include <stdio.h>  // _vsnwprintf()
#include <stdarg.h> // _vsnwprintf()
#include <stdlib.h> // _set_errno() and _CRT_ERRNO_DEFINED
#if !defined(_WIN32_WCE) && defined( _CRT_ERRNO_DEFINED )
#  include <errno.h>  // EINVAL
#endif

#if !defined(_WIN32_WCE)
# define HAS_TEMPNAM
# define HAS_WTEMPNAM
# define HAS_FREOPEN
#endif



/* === add security Check (separately downloadable at MicroSoft */
#if defined( _WIN32_WCE ) && ( _WIN32_WCE < 0x500 ) && ( defined(WIN32_PLATFORM_PSPC) || defined(WIN32_PLATFORM_WFSP) )
	#pragma comment(lib, "ccrtrtti.lib")
	#pragma comment(lib, "secchk.lib" )
	#ifdef _X86_	
		#if defined(_DEBUG)
			#pragma comment(lib, "libcmtx86d.lib")
		#else
			#pragma comment(lib, "libcmtx86.lib")
		#endif
	#endif
#endif

/* === taken from MS Blog somewhere: ==== */
#ifndef   STRINGINZE2_SYMBOL
#  define STRINGINZE2_SYMBOL( sym ) #sym
#endif

#ifndef __TODO__
#  define __STRINGINZE_SYMBOL__(x) STRINGINZE2_SYMBOL(x)
#  define __LOC__  __FILE__ "("__STRINGINZE_SYMBOL__(__LINE__)") : "
#  define __TODO__ __FILE__ "("__STRINGINZE_SYMBOL__(__LINE__)") : ToDo: "
#endif
/* === usage example: 
  #pragma message(__LOC__ "ATN! see here!")
  #pragma message(__TODO__ "to be fixed soon!")
=== */
#define STRINGINZE2_WIDEN(x) L ## x
#define STRINGINZE_WIDEN(x) STRINGINZE2_WIDEN(x)
#define __WFILE__ STRINGINZE_WIDEN(__FILE__)
#define __WFUNC__ STRINGINZE_WIDEN(__FUNCTION__)



/* === add Bjarne Stroustrups _countof() helper from his new Book */
#if !defined(_countof)
#  if !defined(__cplusplus)
#    define _countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#  else
     extern "C++"
       {
       template <typename _CountofType, size_t _SizeOfArray>
       char (*__countof_helper(UNALIGNED _CountofType (&_Array)[_SizeOfArray]))[_SizeOfArray];
       #define _countof(_Array) sizeof(*__countof_helper(_Array))
       }
#  endif
#endif


#if defined(_WIN32_WCE)
/* === add a single symbol from errno.h : wince has no errno, but some API usually return this */
#  ifndef EINVAL
#    define EINVAL 22
#  endif
/* === add a symbol to retrofit abort() like function */
#  if !defined(EXIT_FAILURE)
#    define EXIT_FAILURE -1
#  endif
#  define abort() _exit(EXIT_FAILURE);
#endif


// I need some simple to check signature, so using UINT32 would be fine - why not using my own name?
// written backwards to get it forwards with LE machines
static const unsigned long Signature_Start = 0x4B49414D;  //KIAM
static const unsigned long Signature_End   = 0xE1494552;  //ßIER

static int _crtDbgFlag = _CRTDBG_LEAK_CHECK_DF;  // how to handle all and everything
static int _crtDbgFreq = (_CRTDBG_CHECK_EVERY_1024_DF>>16); // default: do an internal check all 1024 calls
static int _crtDbgCnt  = 0;  // count up and compare to  _crtDbgFreq

static HANDLE DbgHandle[_CRT_ERRCNT] = {(HANDLE) _CRTDBG_INVALID_HFILE,
                                        (HANDLE) _CRTDBG_INVALID_HFILE,
                                        (HANDLE) _CRTDBG_INVALID_HFILE,
                                        (HANDLE) _CRTDBG_INVALID_HFILE };
static int DbgReportMode[_CRT_ERRCNT] = {0};



#define FIL_LIN_FUN     L"%s(%u) : '%s': "               // MSVS lookalike output
#define FIL_LIN_STS_FUN L"%s(%u) : stats s0001: '%s': "  // MSVS lookalike output with STATUS prefix
#define FIL_LIN_ERR_FUN L"%s(%u) : error R0001: '%s': "  // MSVS lookalike output with ERROR prefix
#define FIL_LIN_WRN_FUN L"%s(%u) : warning W0001: '%s': "  // MSVS lookalike output with WARNING prefix
#define FIL_LIN_ASS_FUN L"%s(%u) : assertion A0001: '%s': "  // MSVS lookalike output with ASSERTION prefix

#define ABR_RET_IGN_MSG L"Abort: stop program\r\nRetry: breakpoint\r\nIgnore: ignore it."


#ifdef __cplusplus
  extern "C" {
#endif


typedef enum // all types of what we manage here
  {
    CrtDbgType_Undefined = 0
  , CrtDbgType_CloseHandle  // collective for most Win32 API releases
  , CrtDbgType_HeapMalloc   // malloc, calloc, realloc, strdup, free
  , CrtDbgType_HeapNew      // new / delete
  , CrtDbgType_Win32File    // CreateFile
  , CrtDbgType_Win32MappedFile  // CreateFileForMap
  , CrtDbgType_Win32FileMapping // CreateMapofFile
  , CrtDbgType_Win32MapView // MapView
  , CrtDbgType_Stream       // fopen, _wfopen, fclose, fdup(?)
  , CrtDbgType_WSAStart     // WSAStart / WSACleanup
  , CrtDbgType_WSAService   // WSALookupServiceXxxx
  , CrtDbgType_WSAEvent     // WSAServiceXXX
  , CrtDbgType_Socket       // Socket
  , CrtDbgType_Thread       // CreateThread
  // End of useable List
  , CrtDbg_Last_Type        // 1 index behind last usable entry
  // more to come ... park all not implemented codes here
  , CrtDbgType_Registry     // RegXXXX
  , CrtDbgType_Event        // CreateEvent, CreateMutex, ...
  , CrtDbgType_GDI          // Brush, ...
  , CrtDbgType_Process      // 
  } EN_CRTDBG_TYPES;

/* === which of the above APIs are using CloseHandle in common? */
const EN_CRTDBG_TYPES CloseHandle_Compatible[] = 
  {
    CrtDbgType_Win32File
  , CrtDbgType_Win32MappedFile
  , CrtDbgType_Win32FileMapping
  , CrtDbgType_Event
  , CrtDbgType_Thread
  /*more to come ...*/ 
  };

/* === column entry for the otput helping texts below */
typedef enum { getres=0,relres,unitres, AllocFreeSize } EN_AllocFreeSize;

/* === 2D array, consisting of a row for each API and 3 columns: typical alloc() foo name | typical free() foo name | unit name */
const wchar_t * Names_AllocFree[CrtDbg_Last_Type][AllocFreeSize] = 
  {
    { L"<undef>"       , L"<undef>"        , L"<undef>"   }
  , { L"<win32api>"    , L"CloseHandle"    , L"handle"    }
  , { L"malloc"        , L"free"           , L"byte"      }
  , { L"new"           , L"delete"         , L"byte"      }
  , { L"CreateFile"    , L"CloseHandle"    , L"F_handle"  }
  , { L"CreateFile4Map",L"CloseHandle"    , L"MF_handle" }
  , { L"CreateFileMap" , L"CloseHandle"    , L"FM_handle" }
  , { L"MapViewOfFile" , L"UnmapViewOfFile", L"ViewMap"   }
  , { L"fopen"         , L"fclose"         , L"S_handle"  }
  , { L"WSAStartup"    , L"WSACleanup"     , L"refcount"  }
  , { L"WSALookupSvc"  , L"WSALookupSvcEnd", L"SockServc" }
  , { L"WSACreateEvent", L"WSACloseEvent"  , L"SockEvent" }
  , { L"socket"        , L"closesocket"    , L"SOCKET"    }
//  , { L"RegOpenKey"  , L"RegCloseKey"    , L"R_handle"  }
//  , { L"CreateEvent" , L"CloseHandle"    , L"E_Handle"  }
//  , { L"GetBrush"    , L"ReleaseBrush"   , L"GDI_Obj"   }
  , { L"CreateThread"  , L"CloseHandle"    , L"T_Handle"  }
//  , { L"CreateProcess",L"CloseHandle"   , L"P_Handle"  }
/*
Event (Returned by CreateEvent or OpenEvent.)
Mutex (Returned by CreateMutex.)
Semaphore (Returned by CreateSemaphore.)
*/
  };



/* === This is the Main Control Structure for all and everything inside this library */
typedef struct TS_RessorceWatch_
  {
  TS_RessorceWatch_ * pNext;
  unsigned        FileLine;
	const wchar_t * pFuncName;
	const wchar_t * pFileName;
	wchar_t       * awcObjectName; // Optional, must be allocated/freed before/after use
	EN_CRTDBG_TYPES ResType;
  size_t          MemSize; // or Reference Counter
  const void    * MemAddr;
  const void    * HolderAddr;  // most times empty, because the most common "lvalue = allocation();" doesn't let us know the addr of lvalue :-(
  BOOL            IsIgnoreable; // set expl. to TRUE, if this is out of any checking / reporting
  } TS_RessorceWatch;

/* === Statistics helper */
typedef struct TS_Used_
  {
  size_t Current;
  size_t Max;
  } TS_Used;


/* === Base node of the Main Control & Statistics */
TS_RessorceWatch *pRessourceBlocks = NULL;
TS_Used           Used[ CrtDbg_Last_Type-1 ] = {0};

/* === our bit dirty lock : we can not use CriticalSection API, because we have no Init() like function. And I won't use class here */
typedef struct ELock_
  {
  long lock;
  } TS_ELock, *PTS_ELock;

// our cheap Critical Section - does not need startup-code, so we can use it without InitializeCritical() or any Init() like opener function
TS_ELock _CrtDbg_LOCK     = {0};
TS_ELock _Newhandler_LOCK = {0};
TS_ELock _Usage_LOCK      = {0};
TS_ELock _ResWatch_LOCK   = {0};
TS_ELock _GetName_LOCK    = {0};
TS_ELock _fcloseall_LOCK  = {0};
#ifdef __cplusplus
  }
#endif

/* === Cheap Locking */
inline void EasyLock(   PTS_ELock lock );
inline void EasyUnLock( PTS_ELock lock );

/* === Ressource Management Methods */
inline void Ressource_IncrementCnt( EN_CRTDBG_TYPES type, size_t add );
inline void Ressource_DecrementCnt( EN_CRTDBG_TYPES type, size_t sub );
inline BOOL Ressource_Register(     EN_CRTDBG_TYPES type, size_t bytes, const void *p, bool bMultipleIncrement, 
                                    const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, 
                                    const wchar_t * pObjectName_Optional=NULL,
                                    const void * HolderAddr_Optional=NULL );
inline BOOL Ressource_PreUnregister(EN_CRTDBG_TYPES Type, const void *p,
                                    const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
inline BOOL Ressource_Unregister(   EN_CRTDBG_TYPES Type, const void *p, bool bMultipleDecrement,
                                    const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
inline BOOL Ressource_IsValidType(  EN_CRTDBG_TYPES AllocType, EN_CRTDBG_TYPES FreeType );
inline EN_CRTDBG_TYPES Ressource_GetTypeof( const void *ptr );
static BOOL Ressource_CleanupAll( void );

/* === Ressource Check or MakeCheckable Methods */
inline size_t * Bounds_MakeSignature( unsigned char **pptr, size_t size );
static bool     Bounds_HandleViolation( void **pptr, const WCHAR *pMethodName, 
                                    const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
inline size_t   Bounds_GetAddAlloc( size_t size_of_sizefield );
inline size_t * Bounds_GetRealStart( unsigned char *user_ptr, size_t size_of_sizefield );
inline bool     Bounds_IsUnderRun(   unsigned char *user_ptr );
inline bool     Bounds_IsOverRun(    unsigned char *user_ptr, size_t original_size );

/* === Test, if this is a CrtDbg own ressource and needs to be suppressed 8because deleted at end of the program */
inline BOOL IsIgnoreable( const TS_RessorceWatch *tobechecked );
inline void SetIgnoreable( TS_RessorceWatch *tobechecked, BOOL NewVal );


/* === Some helpers to emulate MS behaviour */
int         _My_set_errno( int err );
static int  _My_CrtDbgReportW_intern( bool BreakAllowed, int reportType, const wchar_t *filename, int linenumber, const wchar_t *moduleName, const wchar_t *format, ... );
static void _My_CrtDbgReportW_intern( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, const wchar_t *format, ... );
static void _My_CrtDbgReportW_intern( const wchar_t *format, ... );

/* === String Output and Formatting */
inline void Cut_CRLF( WCHAR *pString, size_t MaxChar );
static void OutputDebugPrintfW( const WCHAR *fmt, ... );


#ifdef __cplusplus
  extern "C" {
#endif

static wchar_t ExeName[MAX_PATH] = L"";
inline const wchar_t * GetDefaultFile( void )
{{
  EasyLock( &_GetName_LOCK );
  if( !*ExeName )
    {
    if( 0==GetModuleFileName( NULL, ExeName, _countof(ExeName) ) )
      { wcscpy( ExeName, L"unknown file" );
      }
    }
  EasyUnLock( &_GetName_LOCK );
  return ExeName;
}}


static wchar_t FuncName[MAX_PATH] = L"unknown_func";
inline const wchar_t * GetDefaultFunc( void )
{{
  return FuncName;
}}


/* === call the final report on Program exit, if _CRTDBG_LEAK_CHECK_DF was set */
static LONG atexit_handler_CRTDBG_installed = 0;
void atexit_handler_CRTDBG_LEAK_CHECK_DF( void )
{{
  if( _CRTDBG_LEAK_CHECK_DF & _crtDbgFlag )
    {
    const WCHAR * pFunction=L"at exit";
    const WCHAR * ExeName = GetDefaultFile();
    _My_CrtDbgReportW_intern( ExeName, 0, pFunction, L"============================================\r\n" );
    _My_CrtDbgReportW_intern( ExeName, 0, pFunction, L"Leakage Summary at program termination point\r\n" );
    _My_CrtDbgReportW_intern( ExeName, 0, pFunction, L"============================================\r\n" );
    _My_CrtDumpMemoryLeaks2( TRUE, ExeName, 0, pFunction );
    _My_CrtDbgReportW_intern( ExeName, 0, pFunction, L"============================================\r\n" );
    }
}}


static LONG atexit_handler_CLEANUP_installed = 0;
void atexit_handler_CLEANUP( void )
{{
  Ressource_CleanupAll(); // final cleanup
}}


int _My_CrtCheckMemory( void )
{{
  if( _CRTDBG_ALLOC_MEM_DF & _crtDbgFlag )
    {
    _My_CrtDbgReportW_intern( L"_My_CrtCheckMemory() is not yet implemented. Please call _CrtDumpMemoryLeaks() while waiting\r\n" );
#   pragma message(__TODO__ "add walker code here...")
    // this will only be possible if we rigg up the whole malloc()/free() system with defered free(), see _CRTDBG_DELAY_FREE_MEM_DF
    // so the whole number of blocks will allways be in use, only marked as unused.
    return TRUE; // simulate so far: all went fine ... .
    }
  return TRUE; // globally disabled Check
}}

/* To begin dumping from a specified heap state, the state parameter must be a pointer to a _CrtMemState structure 
   that has been filled in by _CrtMemCheckpoint before _CrtMemDumpAllObjectsSince was called. 
   When state is NULL, the function begins the dump from the start of program execution. */
void _My_CrtMemDumpAllObjectsSince( const _CrtMemState *state )
{{
  if( !state )
    { // full dump
    _My_CrtDbgReportW_intern( L"_My_CrtMemDumpAllObjectsSince() is not yet implemented. Please call _CrtDumpMemoryLeaks() while waiting\r\n" );
    }
  else  
    { // dump from state
    _My_CrtDbgReportW_intern( L"_My_CrtMemDumpAllObjectsSince() is not yet implemented.\r\n" );
    }
  return;
}}

void _My_CrtMemCheckpoint( _CrtMemState *state )
{{
  if( state )
    { // *state = current list tip // note: we eventually need to reverse our list, before inserting code here, because our list is currently PREpended
    _My_CrtDbgReportW_intern( L"_My_CrtMemCheckpoint() is not yet implemented.\r\n" );
    }
  return;
}}



// _CRTDBG_CHECK_ALWAYS_DF - Call _CrtCheckMemory at every allocation and deallocation request. OFF: must be called explicitly.
// _CRTDBG_ALLOC_MEM_DF      - if on, each call to alloc/free also calls _CrtCheckMemory()
// _CRTDBG_CHECK_CRT_DF      - trace also RTLib internal RAM -> not implemented, just ignored
// _CRTDBG_DELAY_FREE_MEM_DF - do not really call free, just mark the block as unused and fill with 0xDD, free later
// _CRTDBG_LEAK_CHECK_DF     - ON: Perform automatic leak checking at program exit through a call to _CrtDumpMemoryLeaks()
// _CRTDBG_MM_BOUNDSCHECK - new introduced by REISS: used to control if we add signatures into malloc / check on free to see, if buffer has benn corrupted
int _My_CrtSetDbgFlag( int NewFlag )
{{
  EasyLock( &_CrtDbg_LOCK );
  int oldflag = _crtDbgFlag;
    {
    if( 0==atexit_handler_CLEANUP_installed )
      { atexit_handler_CLEANUP_installed = ! atexit( atexit_handler_CLEANUP );
      }

    if( _CRTDBG_REPORT_FLAG != NewFlag )
      { _crtDbgFlag = (0x0000FFFF & NewFlag);
      }

    if( _CRTDBG_CHECK_ALWAYS_DF & NewFlag )  
      { _crtDbgFreq = 1;
        _crtDbgCnt = 0;
      }
    else if( 0xFFFF0000 & NewFlag )
      { _crtDbgFreq = NewFlag>>16;
        _crtDbgCnt = 0;
      }
      
    if( (_CRTDBG_LEAK_CHECK_DF & _crtDbgFlag) && (0==atexit_handler_CRTDBG_installed) )
      { atexit_handler_CRTDBG_installed = ! atexit( atexit_handler_CRTDBG_LEAK_CHECK_DF );
      }

    }
  EasyUnLock( &_CrtDbg_LOCK );
  return oldflag;
}}


// If you do not call _CrtSetReportMode to define the output destination of messages, then the following defaults are in effect:
//     Assertion failures and errors are directed to a debug message window.
//     Warnings from Windows applications are sent to the debugger's output window.
//     Warnings from console applications are not displayed.
//
// valid types for reportType : _CRT_WARN / _CRT_ERROR / _CRT_ASSERT
// valid types for reportMode : _CRTDBG_MODE_DEBUG / _CRTDBG_MODE_FILE / _CRTDBG_MODE_WNDW ;
//                              or any combination of this.
//                              special case: _CRTDBG_REPORT_MODE returns the above value
int _My_CrtSetReportMode( int reportType, int reportMode )
{{
  EasyLock( &_CrtDbg_LOCK );
  int oldReportMode = -1;
    {
    if( 0==atexit_handler_CLEANUP_installed )
      { atexit_handler_CLEANUP_installed = ! atexit( atexit_handler_CLEANUP );
      }

    if( reportType>=0 && reportType<_CRT_ERRCNT )
      {
      oldReportMode = DbgReportMode[ reportType ];
      if( _CRTDBG_REPORT_MODE != reportMode )
        { DbgReportMode[ reportType ] = reportMode;
        }
      }
    else
      { _My_set_errno(EINVAL);
      }  
    }
  EasyUnLock( &_CrtDbg_LOCK );
  return oldReportMode;
}}


// specify a handle for each of the 3 reportType channels,
// after you called _CrtSetReportMode(reportType,_CRTDBG_MODE_FILE)
// reportFile HANDLE can be any CreateFile() handle or
//                          _CRTDBG_FILE_STDOUT
//                          _CRTDBG_FILE_STDERR
HANDLE _My_CrtSetReportFile( int reportType, HANDLE reportFile )
{{
  EasyLock( &_CrtDbg_LOCK );
  HANDLE OldHnd = (HANDLE) _CRTDBG_INVALID_HFILE;
    {
    if( 0==atexit_handler_CLEANUP_installed )
      { atexit_handler_CLEANUP_installed = ! atexit( atexit_handler_CLEANUP );
      }

    if( reportType>=0 && reportType<_CRT_ERRCNT 
        && (_CRTDBG_MODE_FILE & DbgReportMode[ reportType ]) )
      {
      OldHnd = DbgHandle[ reportType ];
      DbgHandle[ reportType ] = reportFile;
      }
    else
      { _My_set_errno(EINVAL);
        OldHnd = (HANDLE) _CRTDBG_HFILE_ERROR;
      }
    }
  EasyUnLock( &_CrtDbg_LOCK );
  return OldHnd;
}}


/* 8 bit / ascii version of the Report, in case I or U need it. */
int _My_CrtDbgReport( int reportType, const char *filename, int linenumber, const char *moduleName, const char *format, ... )
{{
  const size_t max_chr = 1024;
  char  Buffer[max_chr]="";
  WCHAR filenameW[MAX_PATH]=L"";
  WCHAR modulenameW[MAX_PATH]=L"";
  
  mbstowcs( filenameW  , filename  ?filename  :"", MAX_PATH ); filenameW[   MAX_PATH-1 ] = 0;
  mbstowcs( modulenameW, moduleName?moduleName:"", MAX_PATH ); modulenameW[ MAX_PATH-1 ] = 0;
  
  if( format )
    {
    va_list arglist;
    va_start( arglist, format );
    _vsnprintf( Buffer, max_chr, format, arglist );
    Buffer[ max_chr-1 ] = 0;
    va_end( arglist );
    
    char *pEnd = Buffer + strlen( Buffer );
    // throw away multiple CR/LFs
    while( (pEnd >= Buffer) && (('\r' == *pEnd) || ('\n' == *pEnd) || (!*pEnd)) )
      {
      *pEnd = '\0';
      pEnd--;
      }
    }
  return _My_CrtDbgReportW( reportType, filenameW, linenumber, modulenameW, L"%S\r\n", Buffer );
}}



/* wchar_t / UCS-16 version of the Report, in case I or U need it. */
int _My_CrtDbgReportW( int reportType, const wchar_t *filename, int linenumber, const wchar_t *moduleName, const wchar_t *format, ... )
{{
  const size_t max_chr = 1024;
  WCHAR Buffer[max_chr]=L"";
  if( format )
    {
    va_list arglist;
    va_start( arglist, format );
    _vsnwprintf( Buffer, max_chr, format, arglist );
    Buffer[ max_chr-1 ] = 0;
    va_end( arglist );
    
    Cut_CRLF( Buffer, max_chr ); // throw away multiple CR/LFs
    wcscat( Buffer, L"\r\n" );   // then add a single CR/LF
    }
  return _My_CrtDbgReportW_intern( true, reportType, filename, linenumber, moduleName, L"%s", Buffer );
}}



#ifdef __cplusplus
  }
#endif

static int _My_CrtDbgReportW_intern( bool BreakAllowed, int reportType, const wchar_t *filename, int linenumber, const wchar_t *moduleName, const wchar_t *format, ... )
{{
  int SafeTypeIndex = 0;
  if( reportType>=0 && reportType<_CRT_ERRCNT )
    { SafeTypeIndex = reportType;
    }
  else  
    { _My_set_errno(EINVAL);
      DebugBreak(); // invalid
      return -1;
    }

  const size_t max_chr = 1024;
  size_t Offset;
  WCHAR Buffer[max_chr]=L"";
  
  if( !filename ) filename=L"";
  if( !moduleName ) moduleName=L"";

  switch( SafeTypeIndex )
    {
    case _CRT_WARN  : _snwprintf( Buffer, max_chr, FIL_LIN_WRN_FUN, filename, linenumber, moduleName ); break;
    case _CRT_ERROR : _snwprintf( Buffer, max_chr, FIL_LIN_ERR_FUN, filename, linenumber, moduleName ); break;
    case _CRT_ASSERT: _snwprintf( Buffer, max_chr, FIL_LIN_ASS_FUN, filename, linenumber, moduleName ); break;
    case _CRT_REPORT: _snwprintf( Buffer, max_chr, FIL_LIN_FUN    , filename, linenumber, moduleName ); SafeTypeIndex = _CRT_WARN; break; // since nobody will set _CRT_REPORT-file and bits, I bend it now to be a WARNING
    }

  Buffer[ max_chr-1 ] = 0; // force term char
  Offset = wcslen(Buffer);
  
  if( format )
    {
    va_list arglist;
    va_start( arglist, format );
    _vsnwprintf( Buffer+Offset, max_chr-Offset, format, arglist );
    Buffer[ max_chr-1 ] = 0;
    va_end( arglist );
    
    Cut_CRLF( Buffer, max_chr ); // throw away multiple CR/LFs
    wcscat( Buffer, L"\r\n" );   // then add a single CR/LF
    }

  int ModeBits = DbgReportMode[ SafeTypeIndex ];

  if( _CRTDBG_MODE_DEBUG & ModeBits )
    {
    OutputDebugString( Buffer );
    }
  // Multiple calls at once are valid!
  if( _CRTDBG_MODE_FILE & ModeBits )
    {
    DWORD written=0;
    switch( (long) DbgHandle[ SafeTypeIndex ] )
      {
      case _CRTDBG_FILE_STDOUT : fputws( Buffer, stdout ); break;
      case _CRTDBG_FILE_STDERR : fputws( Buffer, stderr ); break;
      default                  :
        {
        char AsciiBuffer[max_chr]="";
        wcstombs( AsciiBuffer, Buffer, _countof(AsciiBuffer) );
        AsciiBuffer[ _countof(AsciiBuffer)-1 ]=0;
        WriteFile( DbgHandle[ reportType ], AsciiBuffer, (DWORD) strlen(AsciiBuffer), &written, NULL ); 
        };break;
      } // swend
    }
  // Multiple calls at once are valid!
  if( _CRTDBG_MODE_WNDW & ModeBits )
    {
    wcscat( Buffer, ABR_RET_IGN_MSG );
    switch( ::MessageBoxW( NULL, Buffer, moduleName, MB_ABORTRETRYIGNORE | MB_DEFBUTTON2 | MB_APPLMODAL | MB_SETFOREGROUND | MB_TOPMOST ) )
      {
      case IDABORT :
        { 
        abort();
        };break;
      
      case IDRETRY : 
        {
        if( BreakAllowed )
          { DebugBreak();
          }
        }; return -1;
      
      case IDIGNORE:
        { // ignore it
        };break;
      }
    }

  return 0;  
}}

/* a less or more "weak" logging function: */
static void _My_CrtDbgReportW_intern( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, const wchar_t *format, ... )
{{
  
  const size_t max_chr = 1024;
  WCHAR Buffer[max_chr]=L"";
  
  if( format )
    {
    va_list arglist;
    va_start( arglist, format );
    _vsnwprintf( Buffer, max_chr, format, arglist );
    Buffer[ max_chr-1 ] = 0;
    va_end( arglist );
    }

  _My_CrtDbgReportW_intern( false, _CRT_REPORT, pFILE, LINE, pFUNCTION, L"%s", Buffer );
  return;
}}


/* a less or more "weak" logging function: */
static void _My_CrtDbgReportW_intern( const wchar_t *format, ... )
{{
  
  const size_t max_chr = 1024;
  WCHAR Buffer[max_chr]=L"";
  
  if( format )
    {
    va_list arglist;
    va_start( arglist, format );
    _vsnwprintf( Buffer, max_chr, format, arglist );
    Buffer[ max_chr-1 ] = 0;
    va_end( arglist );
    }

  _My_CrtDbgReportW_intern( false, _CRT_REPORT, GetDefaultFile(), 0, GetDefaultFunc(), L"%s", Buffer );
  return;
}}


#ifdef __cplusplus
  extern "C" {
#endif



/* if we can't use Variadic Macros (eVC++4), this one is all U can get */
int _My_CrtDumpMemoryLeaks(void)
{{
  BOOL OnFinalClose = FALSE;
  return _My_CrtDumpMemoryLeaks2( OnFinalClose, GetDefaultFile(), 0, L"global scope" );
}}


/* if we can use Variadic Macros, this one is a bit more comfortable than the previous */
int _My_CrtDumpMemoryLeaks3( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, ... )
{{
  return _My_CrtDumpMemoryLeaks2( FALSE, pFILE, LINE, pFUNCTION );
}}



int _My_CrtDumpMemoryLeaks2( BOOL OnFinalClose, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  int bRet = (int) FALSE;
  int Issues1 = 0, Issues2 = 0, BreakPressed = 0;

  if(!OnFinalClose) _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"===[ CrtDumpMemoryLeaks start]===================\r\n" );
  //-------------------------------------
  // Step 1: report peak usage
  //-------------------------------------
  for( int idx = (int) CrtDbgType_Undefined; idx < _countof(Used) ; idx++ )
    {
    if( (CrtDbgType_Undefined == idx) || (0==Used[idx].Max) )
      { continue;
      }

#   if defined(IGNOREABLES_INTERNALS) && (IGNOREABLES_INTERNALS>0)
    #error continue work tomorrow here - mus reduce .Max by value of ignoreables
    if( IsIgnoreable(idx) )
      { decrement;
      }
#   endif // defined(IGNOREABLES_INTERNALS) && (IGNOREABLES_INTERNALS>0)
    _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, 
                              L"peak ever used %s(): %lu %s, just for information.", 
                              Names_AllocFree[idx][getres],
                              Used[idx].Max, 
                              Names_AllocFree[idx][unitres] );
    }/*for(;;)*/

  //-------------------------------------
  // Step 2: stop on leaks
  //-------------------------------------
  for( int idx = (int) CrtDbgType_Undefined; idx < _countof(Used) ; idx++ )
    {
    if( (CrtDbgType_Undefined == idx) )
      { continue;
      }
#   if defined(IGNOREABLES_INTERNALS) && (IGNOREABLES_INTERNALS>0)
    #error
    if( IsIgnoreable(idx) )
      { decrement;
      }
#   endif // defined(IGNOREABLES_INTERNALS) && (IGNOREABLES_INTERNALS>0)

    if( Used[idx].Current>0 )
      { Issues1++;
        if( -1 == _My_CrtDbgReportW_intern( false, (OnFinalClose)?_CRT_ERROR:_CRT_WARN, pFILE, LINE, pFUNCTION, L"still %lu %s in use by %s()!", 
                                     Used[idx].Current, Names_AllocFree[idx][unitres], Names_AllocFree[idx][getres] ) )
          { BreakPressed++; }
      }
    }/*for(;;)*/
    

  //-------------------------------------
  // Step 3: some friendly information, but only on final close report
  //-------------------------------------
  for( int idx = (int) CrtDbgType_Undefined; OnFinalClose && idx < _countof(Used) ; idx++ )
    {
    if( (CrtDbgType_Undefined == idx) || (CrtDbgType_CloseHandle == idx) )
      { continue;
      }
#   if defined(IGNOREABLES_INTERNALS) && (IGNOREABLES_INTERNALS>0)
    #error
    if( IsIgnoreable(idx) )
      { decrement;
      }
#   endif // defined(IGNOREABLES_INTERNALS) && (IGNOREABLES_INTERNALS>0)
    
    if( (0==Used[idx].Max) && (0==Used[idx].Current) )
      { _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, 
                                  L"%s/%s are okay (or never used).",
                                  Names_AllocFree[idx][getres], Names_AllocFree[idx][relres] );
      }                
    }/*for(;;)*/


  //-------------------------------------
  // Step 4: walk the whole chain
  //-------------------------------------
  EasyLock( &_ResWatch_LOCK );
  for( TS_RessorceWatch * iter = pRessourceBlocks; NULL!=iter ; iter = iter->pNext )
    {
    int idx = (int) iter->ResType;
    // OutputDebugPrintfW( L"WalkingAll: {%s} in 0x%08x", Names_AllocFree[idx][getres], iter );

    if( IsIgnoreable(iter) )
      continue;

    Issues2++;
    if( iter->awcObjectName && *iter->awcObjectName )
      {
      if( -1 == _My_CrtDbgReportW_intern( false, (OnFinalClose)?_CRT_ERROR:_CRT_WARN, iter->pFileName, iter->FileLine, iter->pFuncName, 
                         L"%s(\"%s\",0x%08x,%u) missing for this allocation, or two times allocated to same pointer%s.",
                         Names_AllocFree[idx][relres],
                         iter->awcObjectName,
                         iter->MemAddr, iter->MemSize,
                         (OnFinalClose)?L"":L", or just not closed yet" ) )
        { BreakPressed++; }
      }
    else  
      {
      if( -1 == _My_CrtDbgReportW_intern( false, (OnFinalClose)?_CRT_ERROR:_CRT_WARN, iter->pFileName, iter->FileLine, iter->pFuncName, 
                         L"%s(0x%08x,%u) missing for this allocation, or two times allocated to same pointer%s.",
                         Names_AllocFree[idx][relres],
                         iter->MemAddr, iter->MemSize,
                         (OnFinalClose)?L"":L", or just not closed yet" ) )
        { BreakPressed++; }
      }

    if( -1 == _My_CrtDbgReportW_intern( false, (OnFinalClose)?_CRT_ASSERT:_CRT_WARN, pFILE, LINE, pFUNCTION, 
                       L"%s(0x%08x,%u) missing near here. See previous line for %s() location.",
                       Names_AllocFree[idx][relres],
                       iter->MemAddr, iter->MemSize,
                       Names_AllocFree[idx][getres] ) )
      { BreakPressed++; }
  } // for(;;)
  EasyUnLock( &_ResWatch_LOCK );

  if( _crtDbgFlag & _CRTDBG_CHECK_CRT_DF ) // - not implemented, just ignored
    { _My_CrtDbgReportW_intern( false, _CRT_WARN, pFILE, LINE, pFUNCTION, L"please note: _CRTDBG_CHECK_CRT_DF will never be supported!" );
    }

  if( _crtDbgFlag & _CRTDBG_DELAY_FREE_MEM_DF ) // - not implemented, just ignored
    { _My_CrtDbgReportW_intern( false, _CRT_WARN, pFILE, LINE, pFUNCTION, L"please note: _CRTDBG_DELAY_FREE_MEM_DF is currently not supported!" );
    }

  if( !Issues1 && !Issues2 && !BreakPressed )
    { 
    _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"Nothing to report for now." );
    bRet = (int) TRUE;
    }

  if(!OnFinalClose) _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"===[ CrtDumpMemoryLeaks stopp]===================\r\n" );

  if( BreakPressed )
    DebugBreak();
  return bRet;
}}


#ifdef __cplusplus
  }
#endif


inline void Ressource_IncrementCnt( EN_CRTDBG_TYPES type, size_t add )
{{
  EasyLock( &_Usage_LOCK );
  // OutputDebugPrintfW( L"Increment %lu + %lu = %lu %s", Used[type].Current, add, Used[type].Current + add, Names_AllocFree[type][unitres] );
  Used[type].Current += add;
  if( Used[type].Max < Used[type].Current ) 
    { Used[type].Max = Used[type].Current;
    }
  // OutputDebugPrintfW( L"Increment New Max = %lu %s", Used[type].Max, Names_AllocFree[type][unitres] );
  EasyUnLock( &_Usage_LOCK );
}}

inline void Ressource_DecrementCnt( EN_CRTDBG_TYPES type, size_t sub )
{{
  EasyLock( &_Usage_LOCK );
  // OutputDebugPrintfW( L"Decrement %lu - %lu = %lu %s", Used[type].Current, sub, Used[type].Current - sub, Names_AllocFree[type][unitres] );
  if( Used[type].Current < sub)
    { _MM_DebugBreak();
    }
  Used[type].Current -= sub;
  EasyUnLock( &_Usage_LOCK );
}}


inline size_t Bounds_GetAddAlloc( size_t size_of_sizefield )
{{
  return size_of_sizefield + sizeof(Signature_Start) + sizeof(Signature_End);
}}


inline size_t * Bounds_GetRealStart( unsigned char *user_ptr, size_t size_of_sizefield )
{{
  return (size_t*)( user_ptr - (size_of_sizefield + sizeof(Signature_Start)) );
}}


inline bool Bounds_IsUnderRun( unsigned char *user_ptr )
{{
  unsigned long *pSigStart = (unsigned long*)(user_ptr - (sizeof(Signature_Start)) );
  return (*pSigStart != Signature_Start);
}}


inline bool Bounds_IsOverRun( unsigned char *user_ptr, size_t original_size )
{{
  unsigned long *pSigEnd = (unsigned long*) (user_ptr + original_size);
  return (*pSigEnd != Signature_End);
}}


inline size_t *Bounds_MakeSignature( unsigned char **pptr, size_t size )
{{
  size_t *pRealStart = (size_t*) (*pptr);
  unsigned long *pSigStart, *pSigEnd;
  (*pptr) += sizeof(size_t);
  pSigStart = (unsigned long*) (*pptr);
  (*pptr) += sizeof(Signature_Start); // user data starts here
  pSigEnd = (unsigned long*) ((*pptr) + size);
  *pRealStart= size;
  *pSigStart = Signature_Start;
  *pSigEnd   = Signature_End;
  return pRealStart;
}}


static bool Bounds_HandleViolation( void **pptr, const WCHAR *pMethodName, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  bool bUnderRun = false, bOverRun = false;
  if( pptr && *pptr )
    {
    unsigned char *ptr = (unsigned char *) (*pptr);
    size_t original_size=0;
    size_t add_alloc = Bounds_GetAddAlloc( sizeof(original_size) );
    size_t * pRealStart = Bounds_GetRealStart( ptr, sizeof(original_size) );
    
    (*pptr) = (void*) pRealStart; // correcting the pointer to be the physical one
    bUnderRun = Bounds_IsUnderRun( ptr );

    if( !bUnderRun ) // only if no underrun, we can trust in size
      { original_size = *pRealStart;
        bOverRun = Bounds_IsOverRun( ptr, original_size );
      }

    if( bUnderRun )
      { 
      if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag ) 
        _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, L"BUFFER_UNDERRUN! %s(0x%08x) will probably crash next.\r\n", pMethodName, (*pptr) );
      else if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
        _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x BUFFER_UNDERRUN! %s (physical 0x%08x)\r\n", (*pptr), pMethodName, pRealStart );
      }
    else if( bOverRun )
      { 
      if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag )
        _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, L"BUFFER_OVERRUN! %s(0x%08x) will probably crash next.\r\n", pMethodName, (*pptr) );
      else if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
        _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %u bytes? BUFFER_OVERRUN! %s (physical 0x%08x %u)\r\n", (*pptr), original_size, pMethodName, pRealStart, original_size+add_alloc );
      }
    else if (_CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag) // all okay
      { _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %u bytes, %s in (physical 0x%08x %u)\r\n", (*pptr), original_size, pMethodName, pRealStart, original_size+add_alloc );
      }  
    }
  else if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
    { _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %s\r\n", (*pptr), pMethodName );
    }
  return (!bUnderRun && !bOverRun);
}}





inline BOOL Ressource_Register( EN_CRTDBG_TYPES Type, size_t bytes, const void *p, bool bMultipleIncrement,
                            const wchar_t * pFileName, unsigned line, const wchar_t * pFuncName, 
                            const wchar_t * pObjectName_Optional,
                            const void * HolderAddr_Optional )
{{
  BOOL bRet = FALSE;
  TS_RessorceWatch *pBlock = (TS_RessorceWatch *) (malloc)( sizeof(TS_RessorceWatch) );
  if(!pBlock)
    {
    _My_CrtDbgReportW_intern( true, _CRT_ERROR, __WFILE__, __LINE__, __WFUNC__, L"internal Error, CrtDbg is out of mem\r\n" );
    // OutputDebugPrintfW( L"internal Error, CrtDbg is out of mem\r\n" );
    return FALSE;
    }
  memset( pBlock, 0x00, sizeof(TS_RessorceWatch) )  ;
    
  if( pObjectName_Optional )
    {
    size_t len = 1 + wcslen(pObjectName_Optional);
    pBlock->awcObjectName = (wchar_t*) (malloc)( sizeof(wchar_t) * len );
    if(!pBlock->awcObjectName)
      {
      (free)(pBlock);
      _My_CrtDbgReportW_intern( true, _CRT_ERROR, __WFILE__, __LINE__, __WFUNC__, L"internal Error, CrtDbg is out of mem\r\n" );
      //OutputDebugPrintfW( L"internal Error, CrtDbg is out of mem\r\n" );
      return FALSE;
      }
    wcsncpy( pBlock->awcObjectName, pObjectName_Optional, len );
    }
  
  if( (++_crtDbgCnt == _crtDbgFreq) || (_crtDbgFlag & _CRTDBG_CHECK_ALWAYS_DF ) )
    { _crtDbgCnt = 0;
      _My_CrtCheckMemory();
    }
    
  pBlock->pNext     = NULL;
  pBlock->pFileName = pFileName;
  pBlock->pFuncName = pFuncName;
  pBlock->FileLine  = line;
  pBlock->ResType   = Type;
  pBlock->MemSize   = bytes;
  pBlock->MemAddr   = p;
  pBlock->HolderAddr= HolderAddr_Optional; // most times NULL
  
  Ressource_IncrementCnt( Type, bytes );

  if( pBlock->awcObjectName && *pBlock->awcObjectName )
    { _My_CrtDbgReportW_intern( pFileName, line, pFuncName, L"%s(\"%s\", 0x%08x,%u %s) registered, ok.", 
                                Names_AllocFree[Type][getres], pBlock->awcObjectName, p, bytes, Names_AllocFree[Type][unitres] );
      /* OutputDebugPrintfW( FIL_LIN_STS_FUN L"%s(\"%s\", 0x%08x,%u %s) registered, ok.", 
                      pFileName, line, pFuncName,
                      Names_AllocFree[Type][getres], pBlock->awcObjectName, p, bytes, Names_AllocFree[Type][unitres] ); */
    }
  else  
    { _My_CrtDbgReportW_intern( pFileName, line, pFuncName, L"%s(0x%08x,%u %s) registered, ok.", 
                                Names_AllocFree[Type][getres], p, bytes, Names_AllocFree[Type][unitres] );
      /* OutputDebugPrintfW( FIL_LIN_STS_FUN L"%s(0x%08x,%u %s) registered, ok.", 
                      pFileName, line, pFuncName,
                      Names_AllocFree[Type][getres], p, bytes, Names_AllocFree[Type][unitres] );*/
    }
  
  EasyLock( &_ResWatch_LOCK );
  if( ! pRessourceBlocks )
    {
    pRessourceBlocks = pBlock;
    bRet = TRUE;
    }
  else // insert in Front
    { 
    TS_RessorceWatch * iter;
    for( iter = pRessourceBlocks; iter && iter->MemAddr != p; iter = iter->pNext )
      {;/*just walk*/}
    if( iter && !bMultipleIncrement ) // we stopped above loop before reaching the end: must have been a double use of ->p, and if bMultipleIncrement==false, it's a Failure
      {
#     pragma message(__TODO__ "f.i. put custodial doublettes into a separate 'abandoned' list, this list can be used by the CheckForLeaks function")
      _My_CrtDbgReportW_intern( true, _CRT_ERROR, pFileName, line, pFuncName,
                                L"%s(0x%08x,%u %s) conflicts with %s(0x%08x,%u %s) of " FIL_LIN_FUN, 
                                Names_AllocFree[Type][getres], p            , bytes        , Names_AllocFree[Type][unitres],
                                Names_AllocFree[Type][getres], iter->MemAddr, iter->MemSize, Names_AllocFree[Type][unitres],
                                iter->pFileName, iter->FileLine, iter->pFuncName );
      bRet = FALSE;
      }
    else if( iter && bMultipleIncrement && (iter->ResType==pBlock->ResType) ) // we stopped above loop before reaching the end: must have been a double use of ->p, but if bMultipleIncrement==true, it's okay
      {
      iter->MemSize += pBlock->MemSize; // just increment ressource count
      if( pBlock->awcObjectName )
        { (free)(pBlock->awcObjectName); }
      (free)(pBlock); // no further need of new Block
      bRet = TRUE;
      }
    else
      {
      TS_RessorceWatch *pOldRoot = pRessourceBlocks;
      pRessourceBlocks = pBlock;
      pRessourceBlocks->pNext = pOldRoot;
      bRet = TRUE;
      }
    }
  EasyUnLock( &_ResWatch_LOCK );
  return bRet;
}}


  

inline BOOL Ressource_Unregister( EN_CRTDBG_TYPES Type, const void *p, bool bMultipleDecrement, 
                                  const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const size_t DecrementSize = 1;
  BOOL bRet = FALSE;
  TS_RessorceWatch * iter;
  TS_RessorceWatch * prev = NULL;
  EN_CRTDBG_TYPES AlloType = CrtDbgType_Undefined;

  EasyLock( &_ResWatch_LOCK );
  do{ // } while(0)
    for( iter = pRessourceBlocks; iter && iter->MemAddr != p; prev = iter, iter = iter->pNext )
      {;/*just walk*/}

    // we stopped above loop before reaching the end: must have been an expected entry of ->MemAddr
    if( iter )
      { AlloType = iter->ResType;
      }
    
    if( iter && iter->MemAddr == p ) // found !
      {
      /* if we don't have the location coordinates of free/release/close, but have a iterator with location coordinates of alloc/aquire/open, then just swap for sake of usability */
      const wchar_t *pAlloFILE = (LINE) ? pFILE     : iter->pFileName;
      const wchar_t *pAlloFUNC = (LINE) ? pFUNCTION : iter->pFuncName;
      unsigned        AlloLINE = (LINE) ? LINE      : iter->FileLine;
      const wchar_t *pFreeFILE = (LINE) ? iter->pFileName : pFILE; 
      const wchar_t *pFreeFUNC = (LINE) ? iter->pFuncName : pFUNCTION;
      unsigned        FreeLINE = (LINE) ? iter->FileLine  : LINE;
      
      if( !Ressource_IsValidType( AlloType, Type ) )
        {
        if( 0==LINE )
          { _My_CrtDbgReportW_intern( true, _CRT_ERROR, pAlloFILE, AlloLINE, pAlloFUNC,
                                  L"%s(0x%08x,%u) allocated as type #%u, but INVALID release (%s) as type #%u in " FIL_LIN_FUN,
                                  Names_AllocFree[AlloType][getres], p, iter->MemSize, AlloType, 
                                  Names_AllocFree[Type][relres], Type,
                                  pFreeFILE, FreeLINE, pFreeFUNC );
          }
        else  
          { _My_CrtDbgReportW_intern( true, _CRT_ERROR, pAlloFILE, AlloLINE, pAlloFUNC,
                                  L"%s(0x%08x,%u) INVALID release as type #%u, but allocated (%s) as type #%u in " FIL_LIN_FUN,
                                  Names_AllocFree[Type][relres], p, iter->MemSize, Type, 
                                  Names_AllocFree[AlloType][getres], AlloType,
                                  pFreeFILE, FreeLINE, pFreeFUNC );
          }
        bRet = FALSE;
        break; // break the outmost do-once-loop
        }

      /* === arrived here, all went fine === */
      if( bMultipleDecrement )
        {
        if( iter->MemSize < DecrementSize )
          {
          if( 0==LINE )
            { _My_CrtDbgReportW_intern( true, _CRT_ERROR, pAlloFILE, AlloLINE, pAlloFUNC,
                                    L"%s(0x%08x) referenced %u times, but INVALID dereferenced (%s) %u times " FIL_LIN_FUN,
                                    Names_AllocFree[AlloType][getres], p, iter->MemSize, 
                                    Names_AllocFree[Type][relres], DecrementSize,
                                    pFreeFILE, FreeLINE, pFreeFUNC );
            }
          else  
            { _My_CrtDbgReportW_intern( true, _CRT_ERROR, pAlloFILE, AlloLINE, pAlloFUNC,
                                    L"%s(0x%08x) INVALID dereferenced %u times, but referenced (%s) %u times " FIL_LIN_FUN,
                                    Names_AllocFree[Type][relres], p, DecrementSize,
                                    Names_AllocFree[AlloType][getres], iter->MemSize,
                                    pFreeFILE, FreeLINE, pFreeFUNC );
            }
          bRet = FALSE;
          break; // break the outmost do-once-loop
          }
        
        iter->MemSize -= DecrementSize;
        if( 0==iter->MemSize ) // final release
          { bMultipleDecrement = false;
          }
        }
      
      if( iter->awcObjectName )
        { 
        _My_CrtDbgReportW_intern( true, _CRT_REPORT, pAlloFILE, AlloLINE, pAlloFUNC,
                                  L"%s for %s(\"%s\",0x%08x,%u) in " FIL_LIN_FUN L", ok",
                                  Names_AllocFree[Type][relres], Names_AllocFree[Type][getres], iter->awcObjectName,
                                  p, iter->MemSize,
                                  pFreeFILE, FreeLINE, pFreeFUNC );
        if( !bMultipleDecrement )
          { (free)(iter->awcObjectName);
            iter->awcObjectName = NULL;                        
          }
        }
      else  
        { 
        _My_CrtDbgReportW_intern( true, _CRT_REPORT, pAlloFILE, AlloLINE, pAlloFUNC,
                                  L"%s for %s(0x%08x,%u) in " FIL_LIN_FUN L", ok",
                                  Names_AllocFree[Type][relres], Names_AllocFree[Type][getres],
                                  p, iter->MemSize,
                                  pFreeFILE, FreeLINE, pFreeFUNC );
        }
      Ressource_DecrementCnt( AlloType, iter->MemSize );

      if( !bMultipleDecrement )
        {
        if( prev )
          prev->pNext = iter->pNext; // is follower element
        else
          pRessourceBlocks = iter->pNext; // is root element

        (free)(iter);
        } // if( !bMultipleDecrement )

      if( (++_crtDbgCnt == _crtDbgFreq) || (_crtDbgFlag & _CRTDBG_CHECK_ALWAYS_DF ) )
        { _crtDbgCnt = 0;
          _My_CrtCheckMemory();
        }
        
      bRet = TRUE; // all done well!
      break; // break the outmost do-once-loop
      }
    else // no List or List emptied inbetween
      {
      _My_CrtDbgReportW_intern( true, _CRT_ERROR, pFILE, LINE, pFUNCTION,
                                L"%s(0x%08x,%u) INVALID, nothing to release!",
                                Names_AllocFree[Type][relres], p, 0 );
      }
    } while(0);
  EasyUnLock( &_ResWatch_LOCK );
  
  return bRet;
}}


inline BOOL Ressource_PreUnregister( EN_CRTDBG_TYPES Type, const void *p, 
                                     const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  BOOL bRet = FALSE;
  TS_RessorceWatch * iter;
  TS_RessorceWatch * prev = NULL;
  EN_CRTDBG_TYPES AlloType = CrtDbgType_Undefined;

  EasyLock( &_ResWatch_LOCK );
  do{ // } while(0)
    for( iter = pRessourceBlocks; iter && iter->MemAddr != p; prev = iter, iter = iter->pNext )
      {;/*just walk*/}

    // we stopped above loop before reaching the end: must have been an expected entry of ->MemAddr
    if( iter )
      { AlloType = iter->ResType;
      }
    
    if( iter && iter->MemAddr == p ) // found !
      {
      if( !Ressource_IsValidType( AlloType, Type ) )
        {
        _My_CrtDbgReportW_intern( true, _CRT_ERROR, pFILE, LINE, pFUNCTION,
                                  L"%s(0x%08x,%u) INVALID, release as type #%u / allocated as type #%u (%s)!",
                                  Names_AllocFree[Type][relres], p, iter->MemSize,
                                  Type, AlloType, Names_AllocFree[AlloType][getres] );
        bRet = FALSE;
        break;
        }

      bRet = TRUE; // all done well
      break;
      }
    else // no List or List emptied inbetween
      {
      _My_CrtDbgReportW_intern( true, _CRT_ERROR, pFILE, LINE, pFUNCTION,
                              L"%s(0x%08x,%u) INVALID, nothing to release!",
                              Names_AllocFree[Type][relres], p, 0 );
      }
    } while(0);
  EasyUnLock( &_ResWatch_LOCK );

  return bRet;
}}



static BOOL Ressource_CleanupAll( void )
{{
  BOOL bRet = FALSE;

  EasyLock( &_ResWatch_LOCK );
  if( !pRessourceBlocks )
    {
    bRet = TRUE;
    }
  else
    {
    TS_RessorceWatch * iter;
    for( iter = pRessourceBlocks->pNext; iter ; iter = pRessourceBlocks->pNext )
      {
      if( iter->awcObjectName )
         (free)(iter->awcObjectName);

      pRessourceBlocks->pNext = iter->pNext; // is new root element
      (free)(iter);
      }
    iter = pRessourceBlocks;
    if( iter->awcObjectName )
      (free)(iter->awcObjectName);
    (free)(iter);
    bRet = TRUE;
    }
  EasyUnLock( &_ResWatch_LOCK );  
  return bRet;
}}



inline BOOL IsIgnoreable( const TS_RessorceWatch *tobechecked )
{{
  return tobechecked->IsIgnoreable;
}}


inline void SetIgnoreable( TS_RessorceWatch *tobechecked, BOOL NewVal )
{{
  tobechecked->IsIgnoreable = NewVal;
}}



inline BOOL Ressource_IsValidType( EN_CRTDBG_TYPES AllocType, EN_CRTDBG_TYPES FreeType )
{{
  // CloseHandle_Compatible , CrtDbgType_CloseHandle
  if( CrtDbgType_CloseHandle != FreeType )
    { if( AllocType == FreeType ) 
        { return TRUE;
        }
    }
  else // we have Win32 global "CloseHandle()", so we need to check against all compatible allocations:
    { for( int idx=0 ; idx< _countof(CloseHandle_Compatible) ; idx++ )
        { if( AllocType == CloseHandle_Compatible[idx] )
            { return TRUE;
            }
        }
    }
  return FALSE;   
}}    


inline EN_CRTDBG_TYPES Ressource_GetTypeof( const void *ptr )
{{
  EN_CRTDBG_TYPES tResult = CrtDbgType_Undefined;

  EasyLock( &_ResWatch_LOCK );
  for( TS_RessorceWatch * iter = pRessourceBlocks; NULL!=iter ; iter = iter->pNext )
    {
    if( ptr == iter->MemAddr )
      { tResult = iter->ResType;
        break;
      }
    }
  EasyUnLock( &_ResWatch_LOCK );

  return tResult;
}}    


inline void EasyLock( PTS_ELock lock )
{{
  while( InterlockedIncrement( &lock->lock ) > 1 )
    {// coming here, a second thread has locked nearly same time
    //  so we release our own lock
    InterlockedDecrement( &lock->lock );
    // and sleep a very little time (but not ZERO!!! -> see why: <http://blogs.msdn.com/b/oldnewthing/archive/2005/10/04/476847.aspx>)
    Sleep(1); 
    }
  // coming here you are exclusive until ... ... releasing the lock
  return;
}}

inline void EasyUnLock( PTS_ELock lock )
{{ // ... releasing the lock
  InterlockedDecrement( &lock->lock );
  return;
}}





int _My_set_errno( int err )
{{
# if !defined(_WIN32_WCE) && defined( _CRT_ERRNO_DEFINED )
  return (int) _set_errno( err );
# else
  return 0;
# endif         
}}


inline void Cut_CRLF( WCHAR *pString, size_t MaxChar )
{{
  WCHAR *pEnd = pString + wcslen( pString );
  // throw away multiple CR/LFs
  while( (pEnd >= pString) && ((L'\r' == *pEnd) || (L'\n' == *pEnd) || (!*pEnd)) )
    {
    *pEnd = L'\0';
    pEnd--;
    }
  if(MaxChar>=3)
    pString[ MaxChar-3 ] = 0; // ensure space for new end
  return;  
}}



static void OutputDebugPrintfW( const WCHAR *fmt, ... )
{{
  va_list arglist;
  const size_t max_chr = 1024;
  WCHAR Buffer[max_chr];
  va_start( arglist, fmt );
  _vsnwprintf( Buffer, max_chr, fmt, arglist );
  Buffer[ max_chr-1 ] = 0;
  va_end( arglist );
  
  Cut_CRLF( Buffer, max_chr ); // throw away multiple CR/LFs
  wcscat( Buffer, L"\r\n" );   // then add a single CR/LF
  OutputDebugStringW( Buffer );
  return;
}}


/* ================================================================= *
 * PART B)                                                           *
 * The Interface of watched APIs                                     *
 * Here, we define which Win32 API is controlled. We may add more.   *
 *                                                                   *
 * ================================================================= */
#ifdef __cplusplus
  extern "C" {
#endif

/* ========================================================================================= */
/* ===[ CrtDbgType_HeapMalloc ] ============================================================ */
/* ========================================================================================= */
/* = malloc(), calloc() and free() of the Std-C-API                                        = */
/* ========================================================================================= */
void* dbg_malloc2( size_t size, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, const WCHAR * pMethodName )
{{
  size_t alloc_size = size;
  size_t add_alloc = 0;
  if(!pMethodName || !*pMethodName) pMethodName = L"alloc";

  if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag )
    { add_alloc = Bounds_GetAddAlloc( sizeof(size) );
    }

  unsigned char *ptr = (unsigned char *)((malloc)(size+add_alloc));

  if( ptr && (_CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag) )
    {
    size_t *pRealStart = Bounds_MakeSignature( &ptr, size );

    if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
      { _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %u bytes, %s (physical 0x%08x %u)\r\n", ptr, size, pMethodName, pRealStart, size+add_alloc );
      }
    
    if( !Ressource_Register( CrtDbgType_HeapMalloc, size + add_alloc, (void*) pRealStart, false, pFILE, LINE, pFUNCTION ) )
      { _MM_DebugBreak(); }

    return (void*) ptr;
    } // if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag )

  if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
    { _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %u bytes, %s\r\n", ptr, size, pMethodName );
    }

  if( ! Ressource_Register( CrtDbgType_HeapMalloc, size, (void*) ptr, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return (void*) ptr;
}}



void* dbg_malloc( size_t size, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"malloc";
  return dbg_malloc2( size, pFILE, LINE, pFUNCTION, pMethodName );
}}




void* dbg_calloc( size_t num, size_t size, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"calloc";
  size_t sum_size = num * size;
  void *ptr = dbg_malloc2( sum_size, pFILE, LINE, pFUNCTION, pMethodName );
  if(ptr) memset( ptr, 0x00, sum_size );
  return ptr;
}}



void* dbg_realloc( void* oldaddr, size_t newsize, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"realloc";
  size_t alloc_size = newsize;
  size_t add_alloc = 0;
#pragma message(__TODO__ "pre_unregister" )
  if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag )
    { add_alloc = Bounds_GetAddAlloc( sizeof(newsize) );
      if( ! Bounds_HandleViolation( &oldaddr, pMethodName, pFILE, LINE, pFUNCTION ) )
        { _MM_DebugBreak();
        };
    }  
  else if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
    {_My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %u bytes, %s\r\n", oldaddr, newsize, pMethodName );
    }

  void *newaddr = (realloc)( oldaddr, alloc_size + add_alloc );

  if( ((oldaddr) && !Ressource_Unregister( CrtDbgType_HeapMalloc,             oldaddr, false, pFILE, LINE, pFUNCTION )) || 
      (             !Ressource_Register(   CrtDbgType_HeapMalloc, alloc_size, newaddr, false, pFILE, LINE, pFUNCTION ))    )
    { _MM_DebugBreak(); }

  if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
    {_My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %u bytes, %s\r\n", newaddr, newsize, pMethodName );
    }

  return newaddr;
}}



char *dbg_strdupA( const char *ptr, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"strdupA";
  if(ptr)
    {
    size_t sum_size = 1+strlen(ptr);
    char *copy = (char *) dbg_malloc2( sum_size, pFILE, LINE, pFUNCTION, pMethodName );
    if(copy) memcpy( copy, ptr, sum_size );
    return copy;
    }
  return NULL;  
}}



wchar_t *dbg_strdupW( const wchar_t *ptr, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"strdupW";
  if(ptr)
    {
    size_t sum_size = sizeof(wchar_t) * (1+wcslen(ptr));
    wchar_t *copy = (wchar_t *) dbg_malloc2( sum_size, pFILE, LINE, pFUNCTION, pMethodName );
    if(copy) memcpy( copy, ptr, sum_size );
    return copy;
    }
  return NULL;  
}}


char *dbg_tempnam( const char *dir, const char *prefix, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"tempnam";
# if defined(HAS_TEMPNAM)
  char *ptr;
  ptr = (_tempnam)( dir, prefix );
  if(ptr)
    {
    size_t sum_size = sizeof(char) * (1+strlen(ptr));
    char *copy = (char*) dbg_malloc2( sum_size, pFILE, LINE, pFUNCTION, pMethodName );
    if(copy) memcpy( copy, ptr, sum_size );
    return copy;
    }
# else //defined(HAS_TEMPNAM)
  _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"this SDK has no  %s()!", pMethodName );
# endif //defined(HAS_TEMPNAM)
  return NULL;  
}}


wchar_t *dbg_wtempnam( const wchar_t *dir, const wchar_t *prefix, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"wtempnam";
#if defined(HAS_WTEMPNAM)
  wchar_t *ptr;
  ptr = (_wtempnam)( dir, prefix );
  if(ptr)
    {
    size_t sum_size = sizeof(wchar_t) * (1+wcslen(ptr));
    wchar_t *copy = (wchar_t*) dbg_malloc2( sum_size, pFILE, LINE, pFUNCTION, pMethodName );
    if(copy) memcpy( copy, ptr, sum_size );
    return copy;
    }
# else //defined(HAS_WTEMPNAM)
  _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"this SDK has no %s()!", pMethodName );
#endif //defined(HAS_WTEMPNAM)
  return NULL;  
}}



void dbg_free( void *p, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"free";
  if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag )
    { if( ! Bounds_HandleViolation( &p, pMethodName, pFILE, LINE, pFUNCTION ) )
        { _MM_DebugBreak();
        };
    }  
  else if( p && ! Ressource_PreUnregister( CrtDbgType_HeapMalloc, p, pFILE, LINE, pFUNCTION ) )
    { _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, 
                          L"%s(0x%08x) will probably crash now...\r\n", 
                          pMethodName, p );
    }
  else if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
    {_My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %s\r\n", p, pMethodName );
    }
   
  (free)( p );

  if( p && ! Ressource_Unregister( CrtDbgType_HeapMalloc, p, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return;
}}





/* ========================================================================================= */
/* ===[ CrtDbgType_HeapNew ] =============================================================== */
/* ========================================================================================= */
/* = operator new() and operator delete of the C++ RTL / Standard Library                  = */
/* ========================================================================================= */
#ifdef __cplusplus
  }
#endif

#ifdef __cplusplus
#if defined(DEBUG_NEW) || (1)
#include <new> // std::bad_alloc

static _dbg_PNH dbg_new_handler = NULL;
_dbg_PNH _dbg_set_new_handler( _dbg_PNH pNewHandler )
{{
  _dbg_PNH Old_Ptr = NULL;
  EasyLock( &_Newhandler_LOCK );
  Old_Ptr = dbg_new_handler;
  dbg_new_handler = pNewHandler;
  EasyUnLock( &_Newhandler_LOCK );
  return Old_Ptr;
}}


// use the "placement" version of new
void * operator new( size_t size, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, const WCHAR * pMethodName )
       throw(...)
{{
  unsigned char *ptr;
  if( !pMethodName || !*pMethodName ) pMethodName = L"new";

  size_t alloc_size = size;
  size_t add_alloc = 0;

  if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag )
    { add_alloc = Bounds_GetAddAlloc( sizeof(size) );
    }

  while( true )
    {
    ptr = (unsigned char *)((malloc)(size+add_alloc));
    
    if( ptr && (_CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag) )
      {
      size_t *pRealStart = Bounds_MakeSignature( &ptr, size );

      if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
        { _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %u bytes, %s (physical 0x%08x %u)\r\n", ptr, size, pMethodName, pRealStart, size+add_alloc );
        }
      
      if( !Ressource_Register( CrtDbgType_HeapNew, size + add_alloc, (void*) pRealStart, false, pFILE, LINE, pFUNCTION ) )
        { _MM_DebugBreak(); }

      return (void*) ptr;
      } // if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag )
    else if( ptr ) // ~_CRTDBG_MM_BOUNDSCHECK
      {
      if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
        { _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %u bytes, %s\r\n", ptr, size, pMethodName );
        }

      if( ! Ressource_Register( CrtDbgType_HeapNew, size, (void*) ptr, false, pFILE, LINE, pFUNCTION ) )
        { _MM_DebugBreak(); }

      return (void*) ptr;
      }
    else // ptr==NULL returned
      {
      EasyLock( &_Newhandler_LOCK );
      _dbg_PNH __current_new_handler = dbg_new_handler;
      EasyUnLock( &_Newhandler_LOCK );

      if( NULL==__current_new_handler )
        { 
        WCHAR locationW[MAX_PATH];
        char  locationA[MAX_PATH];
        _snwprintf( locationW, _countof(locationW), FIL_LIN_ERR_FUN L"out of mem for %u bytes.", pFILE, LINE, pFUNCTION, size );
        locationW[ _countof(locationW)-1 ] = 0;
        wcstombs( locationA, locationW, _countof(locationA) );
        throw std::bad_alloc( locationA );
        }
      else
        {
        (*__current_new_handler)();
        }  
      /* give it one more try*/
      }
    } // end-of-while( true ), will never be reached by design
  return NULL;  
}}


void * operator new( size_t size, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
       throw(...)
{{
  const WCHAR * pMethodName = L"new (f,l,f)";
  return ::operator new( size, pFILE, LINE, pFUNCTION, pMethodName );
}}


void * operator new[] ( size_t size, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
       throw(...)
{{
  const WCHAR * pMethodName = L"new (f,l,f) []";
  return ::operator new( size, pFILE, LINE, pFUNCTION, pMethodName );
}}


void * operator new( size_t size )
       throw(...)
{{
  const WCHAR * pMethodName = L"new";
  return ::operator new( size, GetDefaultFile(), 0, GetDefaultFunc(), pMethodName );
}}


void * operator new[] ( size_t size )
       throw(...)
{{
  const WCHAR * pMethodName = L"new []";
  return ::operator new( size, GetDefaultFile(), 0, GetDefaultFunc(), pMethodName );
}}


void operator delete( void * ptr, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, const WCHAR * pMethodName )
     throw()
{{
  if( !pMethodName || !*pMethodName ) pMethodName = L"delete (f,l,f,m)";
  if( _CRTDBG_MM_BOUNDSCHECK & _crtDbgFlag )
    { if( ! Bounds_HandleViolation( &ptr, pMethodName, pFILE, LINE, pFUNCTION ) )
        { _MM_DebugBreak();
        };
    }  
  else if( ptr && ! Ressource_PreUnregister( CrtDbgType_HeapNew, ptr, pFILE, LINE, pFUNCTION ) )
    { _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, 
                          L"%s(0x%08x) will probably crash now...\r\n", 
                          pMethodName, ptr );
    }
  else if( _CRTDBG_MM_CHATTY_ALLOCFREE & _crtDbgFlag )
    { _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"MDBG: 0x%08x %s\r\n", ptr, pMethodName );
    }
   
  (free)(ptr);

  if( ptr && ! Ressource_Unregister( CrtDbgType_HeapNew, ptr, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }
  return;  
}}


void operator delete( void * ptr, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
     throw()
{{
  const WCHAR * pMethodName = L"delete (f,l,f)";
  ::operator delete( ptr, pFILE, LINE, pFUNCTION, pMethodName );
  return;  
}}

void operator delete[]( void * ptr, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
      throw()
{{
  const WCHAR * pMethodName = L"delete [](f,l,f)";
  ::operator delete( ptr, pFILE, LINE, pFUNCTION, pMethodName );
  return;  
}}

void operator delete( void * ptr )
     throw()
{{
  const WCHAR * pMethodName = L"delete";
  ::operator delete( ptr, GetDefaultFile(), 0, GetDefaultFunc(), pMethodName );
  return;  
}}


void operator delete[]( void * ptr )
     throw()
{{
  const WCHAR * pMethodName = L"delete[]";
  ::operator delete( ptr, GetDefaultFile(), 0, GetDefaultFunc(), pMethodName );
  return;  
}}


#endif
#endif // def __cplusplus

#ifdef __cplusplus
  extern "C" {
#endif


/* ========================================================================================= */
/* ===[ CrtDbgType_Win32File ] ============================================================= */
/* ========================================================================================= */
/* = CreateFileW() of the Win32 API (no CreateFileA(), because WinCE doesn't have it)      = */
/* = CloseHandle() of the Win32 API NOTE: CloseHandle will be used for a lot of APIs       = */
/* = How about DuplicateHandle() ???                                                       = */
/* ========================================================================================= */
HANDLE dbg_CreateFileW( LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                        DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
                        const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"CreateFile";
  HANDLE Handle = INVALID_HANDLE_VALUE;
  Handle = (CreateFileW)( lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile );

  if( (INVALID_HANDLE_VALUE!=Handle) && ! Ressource_Register( CrtDbgType_Win32File, 1, (void*) Handle, false, pFILE, LINE, pFUNCTION, lpFileName ) )
    { _MM_DebugBreak(); }

  return Handle;
}}


#if defined( _WIN32_WCE )
/* this usually does not create LEAKs, but for 'clean code development' rules, we will rant anyway... */
HANDLE dbg_CreateFileForMapping( LPCTSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
                           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
                           const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"CreateFileForMapping";
  HANDLE Handle = INVALID_HANDLE_VALUE;
  Handle = (CreateFileForMappingW)( lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile );

  if( (INVALID_HANDLE_VALUE!=Handle) && ! Ressource_Register( CrtDbgType_Win32MappedFile, 1, (void*) Handle, false, pFILE, LINE, pFUNCTION, lpFileName ) )
    { _MM_DebugBreak(); }

  return Handle;
}}
#endif //defined( _WIN32_WCE )


// If you call CreateFileMapping with a handle from CreateFileForMapping and it fails for any reason, the handle is closed.
// Creating a file-mapping object creates the potential for mapping a view of the file but does not map the view. 
// The MapViewOfFile function maps a view of a file into the address space of a process. 
HANDLE dbg_CreateFileMapping( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, 
                           DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName,
                           const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"CreateFileMapping";
  HANDLE Handle = INVALID_HANDLE_VALUE;
  Handle = (CreateFileMappingW)( hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName );

  if( NULL!=Handle )
    { if( ! Ressource_Register( CrtDbgType_Win32FileMapping, 1, (void*) Handle, false, pFILE, LINE, pFUNCTION, lpName ) )
        { _MM_DebugBreak(); }
    }
  else // NULL
    { EN_CRTDBG_TYPES ItsType = Ressource_GetTypeof( (void*) hFile );
      if( CrtDbgType_Win32MappedFile == ItsType ) // if type is CrtDbgType_Win32MappedFile instead of CrtDbgType_Win32File and foo fails, implicitely call CloseHandle
        { dbg_CloseHandle( hFile, pFILE, LINE, pFUNCTION );
        }
    }

  return Handle;
}}

// The MapViewOfFile function maps a view of a file into the address space of a process. 
// To fully close a file-mapping object, an application must unmap all mapped views of the file-mapping object by calling UnmapViewOfFile, 
// and close the file-mapping object handle by calling CloseHandle. The order in which these functions are called does not matter.
// The call to UnmapViewOfFile is necessary because mapped views of a file-mapping object maintain internal open handles to the object, 
// and a file-mapping object will not close until all open handles to it are closed.
void * dbg_MapViewOfFile( HANDLE hFileMappingObject, DWORD dwDesiredAccess, 
                          DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, DWORD dwNumberOfBytesToMap, 
                          const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  // increment reference counter on each call of same object.
  const WCHAR * pMethodName = L"MapViewOfFile";
  void * ptr = NULL;
  ptr = (MapViewOfFile)( hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap );

  if( (NULL!=ptr) && ! Ressource_Register( CrtDbgType_Win32MapView, 1, (void*) ptr, true, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return ptr;
}}


//Although an application may close the file handle used to create a file-mapping object, the system holds the corresponding file open until the last view of the file is unmapped.
BOOL dbg_UnmapViewOfFile( const void *lpBaseAddress, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
 // if reference counter is back to 0 and close has been called befor (how to see this???) the implicitely/delayed call close
 // best way is to just ignore this connection and handle both handles disconnected
  const WCHAR * pMethodName = L"UnmapViewOfFile";
  BOOL bRet = FALSE;

  if( ! Ressource_PreUnregister( CrtDbgType_Win32MapView, lpBaseAddress, pFILE, LINE, pFUNCTION ) )
    { _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, 
                          L"%s(0x%08x) will probably crash now...\r\n", 
                          pMethodName, lpBaseAddress );
    }

  bRet = (UnmapViewOfFile)( lpBaseAddress );

  if( bRet && ! Ressource_Unregister( CrtDbgType_CloseHandle, lpBaseAddress, true, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return bRet;
}}


// __TODO__ For Windows CE, it is only necessary to close the mapping handle as the file handle is automatically closed when you close the mapping handle.
BOOL dbg_CloseHandle( HANDLE Handle, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"CloseHandle";
  BOOL bRet = FALSE;

  if( INVALID_HANDLE_VALUE!=Handle && ! Ressource_PreUnregister( CrtDbgType_CloseHandle, Handle, pFILE, LINE, pFUNCTION ) )
    { _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, 
                          L"%s(0x%08x) will probably crash now...\r\n", 
                          pMethodName, Handle );
    }

  bRet = (CloseHandle)( Handle );

  if( bRet && ! Ressource_Unregister( CrtDbgType_CloseHandle, (void*) Handle, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return bRet;
}}



BOOL dbg_DuplicateHandle(  HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
                           LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions,
                           const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"DuplicateHandle";
  BOOL bRet = FALSE;
  DWORD FakeOptions = dwOptions & ~DUPLICATE_CLOSE_SOURCE;
  
  bRet = (DuplicateHandle)( hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, FakeOptions );
  EN_CRTDBG_TYPES ThisType = Ressource_GetTypeof( (void*) hSourceHandle ); // CrtDbgType_Win32File or other;

  if( bRet && lpTargetHandle && (INVALID_HANDLE_VALUE!=*lpTargetHandle) && 
     ! Ressource_Register( ThisType, 1, (void*) *lpTargetHandle, false, pFILE, LINE, pFUNCTION, NULL ) )
    { _MM_DebugBreak(); }

  if( dwOptions & DUPLICATE_CLOSE_SOURCE )
    { dbg_CloseHandle( hSourceHandle, pFILE, LINE, pFUNCTION );
    }
  return bRet;
}}


/* ========================================================================================= */
/* ===[ CrtDbgType_Stream ] ================================================================ */
/* ========================================================================================= */
/* = fopen() wfopen() and fclose() of the Std-C-API                                        = */
/* = may be also comming: fdup(), freopen() ???                                            = */
/* ========================================================================================= */
#pragma message( __TODO__ "add Invalid Parameter Handler Routine")

static int dbg_fclose2( FILE* Stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, const WCHAR * pMethodName ) // fclose returns 0 if the stream is successfully closed, returns EOF to indicate an error.
{{
  int iRet = EOF;

  if( ! Ressource_PreUnregister( CrtDbgType_Stream, Stream, pFILE, LINE, pFUNCTION ) )
    { _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, 
                          L"%s(0x%08x) will probably crash now...\r\n", 
                          pMethodName, Stream );
    }

  iRet = (fclose)( Stream );

  if( (0==iRet) && ! Ressource_Unregister( CrtDbgType_Stream, (void*) Stream, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return iRet;
}}


int dbg_fcloseall( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION ) // _fcloseall returns the total number of streams closed, returns EOF to indicate an error.
{{
  const WCHAR * pMethodName = L"fcloseall";
  int closed = 0;

  EasyLock( &_fcloseall_LOCK );
  for( TS_RessorceWatch * iter = pRessourceBlocks; NULL!=iter ; iter = iter->pNext )
    {
    if( CrtDbgType_Stream == iter->ResType )
      {
      if( 0==dbg_fclose2( (FILE*) iter->MemAddr, pFILE, LINE, pFUNCTION, pMethodName ) ) // invalidates iter!
        {
        closed++;
        iter = pRessourceBlocks; // restart iterator
        }
      }
    }
  EasyUnLock( &_fcloseall_LOCK );
  return closed;
}}


int dbg_fclose( FILE* Stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION ) // fclose returns 0 if the stream is successfully closed, returns EOF to indicate an error.
{{
  const WCHAR * pMethodName = L"fclose";
  return dbg_fclose2( Stream, pFILE, LINE, pFUNCTION, pMethodName );
}}


FILE *dbg_fopen( const char *filename8, const char *mode8, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"fopen";
  FILE *Handle = NULL;
  size_t len = sizeof(char) * (1+strlen(filename8));
  wchar_t *filenameW = (wchar_t*)(malloc)(len);
  if( filenameW )
    {
    mbstowcs( filenameW, filename8, len );
    filenameW[ len-1 ] = 0;
    }
      
  Handle = (fopen)( filename8, mode8 );
  
  if( (NULL!=Handle) && ! Ressource_Register( CrtDbgType_Stream, 1, (void*) Handle, false, pFILE, LINE, pFUNCTION, filenameW/*okay if 0*/ ) )
    { _MM_DebugBreak(); }

  (free)((void*)filenameW);
  return Handle;
}}


FILE *dbg_wfopen( const wchar_t *filenameW, const wchar_t *modeW, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"wfopen";
  FILE *Handle = NULL;
  Handle = (_wfopen)( filenameW, modeW );

  if( (NULL!=Handle) && ! Ressource_Register( CrtDbgType_Stream, 1, (void*) Handle, false, pFILE, LINE, pFUNCTION, filenameW ) )
    { _MM_DebugBreak(); }

  return Handle;
}}


FILE *dbg_freopen( const char *filename8, const char *mode8, FILE *stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"freopen";
  FILE *Handle = NULL;
# if defined(HAS_FREOPEN)
  if( !stream || !filename8 || !mode8 ) 
    return NULL;

  size_t len = sizeof(char) * (1+strlen(filename8));
  wchar_t *filenameW = (wchar_t*)(malloc)(len);
  if( filenameW )
    {
    mbstowcs( filenameW, filename8, len );
    filenameW[ len-1 ] = 0;
    }
#pragma message(__TODO__ "ressource_pre_unregister")      
  Handle = (freopen)( filename8, mode8, stream );

  if( (NULL!=Handle) && ! Ressource_Register( CrtDbgType_Stream, 1, (void*) Handle, false, pFILE, LINE, pFUNCTION, filenameW ) )
    { _MM_DebugBreak(); }

  /*unconditional: */
  Ressource_Unregister( CrtDbgType_Stream, (void*) stream, false, pFILE, LINE, pFUNCTION );
  (free)(filenameW);

# else //defined(HAS_FREOPEN)
  _My_CrtDbgReportW_intern( pFILE, LINE, pFUNCTION, L"this SDK has no  %s()!", pMethodName );
# endif //defined(HAS_FREOPEN)
  return Handle;
}}


FILE *dbg_wfreopen( const wchar_t *filenameW, const wchar_t *modeW, FILE *stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"wfreopen";
  FILE *Handle = NULL;
  if( !stream || !filenameW || !modeW ) 
    return NULL;
#pragma message(__TODO__ "ressource_pre_unregister")
  Handle = (_wfreopen)( filenameW, modeW, stream );

  if( (NULL!=Handle) && ! Ressource_Register( CrtDbgType_Stream, 1, (void*) Handle, false, pFILE, LINE, pFUNCTION, filenameW ) )
    { _MM_DebugBreak(); }

  /*unconditional: */
  Ressource_Unregister( CrtDbgType_Stream, (void*) stream, false, pFILE, LINE, pFUNCTION );

  return Handle;
}}


#if !defined( _WIN32_WCE ) || (defined( _WIN32_WCE ) && ( _WIN32_WCE >= 0x500 ))
// _s secure API 1st avail under CE5 and higher
errno_t dbg_fopen_s( FILE** ppStream, const char *filename8, const char *mode8, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )  // EINVAL, 0 on okay
{{
  const WCHAR * pMethodName = L"fopen_s";
  if( !ppStream || !filename8 || !mode8 ) 
    return EINVAL;

  errno_t res;
  size_t len = sizeof(char) * (1+strlen(filename8));
  wchar_t *filenameW = (wchar_t*)(malloc)(len);
  if( filenameW )
    {
    mbstowcs( filenameW, filename8, len );
    filenameW[ len-1 ] = 0;
    }
      
  res = (fopen_s)( ppStream, filename8, mode8 );

  if( (0==res) && (*ppStream) && ! Ressource_Register( CrtDbgType_Stream, 1, (void*) *ppStream, false, pFILE, LINE, pFUNCTION, filenameW ) )
    { _MM_DebugBreak(); }

  (free)(filenameW);
  return res;
}}


errno_t dbg_wfopen_s( FILE** ppStream, const wchar_t *filenameW, const wchar_t *modeW, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )  // EINVAL, 0 on okay
{{
  const WCHAR * pMethodName = L"wfopen_s";
  if( !ppStream || !filenameW || !modeW ) 
    return EINVAL;

  errno_t res;
  res = (_wfopen_s)( ppStream, filenameW, modeW );

  if( (0==res) && (*ppStream) && ! Ressource_Register( CrtDbgType_Stream, 1, (void*) *ppStream, false, pFILE, LINE, pFUNCTION, filenameW ) )
    { _MM_DebugBreak(); }

  return res;
}}


errno_t dbg_freopen_s( FILE** ppStream, const char *filename8, const char *mode8, FILE *stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"freopen_s";
  errno_t res;
  if( !ppStream || !filename8 || !mode8 || !stream ) 
    return EINVAL;

  size_t len = sizeof(char) * (1+strlen(filename8));
  wchar_t *filenameW = (wchar_t*)(malloc)(len);
  if( filenameW )
    {
    mbstowcs( filenameW, filename8, len );
    filenameW[ len-1 ] = 0;
    }
#pragma message(__TODO__ "ressource_pre_unregister" )

  res = (freopen_s)( ppStream, filename8, mode8, stream );

  if( (0==res) && (*ppStream) && ! Ressource_Register( CrtDbgType_Stream, 1, (void*) *ppStream, false, pFILE, LINE, pFUNCTION, filenameW ) )
    { _MM_DebugBreak(); }

  /*unconditional: */
  Ressource_Unregister( CrtDbgType_Stream, (void*) stream, false, pFILE, LINE, pFUNCTION );
  (free)(filenameW);

  return res;
}}

errno_t dbg_wfreopen_s( FILE** ppStream, const wchar_t *filenameW, const wchar_t *modeW, FILE *stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"wfreopen_s";
  errno_t res;
  if( !ppStream || !filenameW || !modeW || !stream ) 
    return EINVAL;
#pragma message(__TODO__ "ressource_pre_unregister")
  res = (_wfreopen_s)( ppStream, filenameW, modeW, stream );

  if( (0==res) && (*ppStream) && ! Ressource_Register( CrtDbgType_Stream, 1, (void*) *ppStream, false, pFILE, LINE, pFUNCTION, filenameW ) )
    { _MM_DebugBreak(); }

  /*unconditional: */
  Ressource_Unregister( CrtDbgType_Stream, (void*) stream, false, pFILE, LINE, pFUNCTION );

  return res;
}}
#endif //!defined( _WIN32_WCE ) || (defined( _WIN32_WCE ) && ( _WIN32_WCE >= 0x500 ))

/* ========================================================================================= */
/* ===[ CrtDbgType_WSAStart   ] ============================================================ */
/* ===[ CrtDbgType_WSAStart   ] ============================================================ */
/* ===[ CrtDbgType_WSAService ] ============================================================ */
/* ===[ CrtDbgType_WSAEvent   ] ============================================================ */
/* ===[ CrtDbgType_Socket     ] ============================================================ */
/* ========================================================================================= */
#if !defined( CRTDBG_NO_WS )
int dbg_WSAStartup( WORD Ver, LPWSADATA pWSA, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"WSAStartup";
  int res = (WSAStartup)( Ver, pWSA );
  if( 0==res && ! Ressource_Register( CrtDbgType_WSAStart, 1, (void*) 0xBADFACE, true, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }
  return res;    
}}


int dbg_WSACleanup( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"WSACleanup";
  #undef WSACleanup
#pragma message(__TODO__ "ressource_pre_unregister")
  int res = (WSACleanup)();
  if( (0==res) && ! Ressource_Unregister( CrtDbgType_WSAStart, (void*) 0xBADFACE, true, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }
  return res;    
}}


SOCKET dbg_socket( int af, int type, int prot, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"socket";
  SOCKET s = (socket)( af, type, prot );
  if( (INVALID_SOCKET!=s) && ! Ressource_Register( CrtDbgType_Socket, 1, (void*) s, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }
  return s;
}}


SOCKET dbg_accept( SOCKET s, struct sockaddr FAR* addr, int FAR* addrlen, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"accept";
  SOCKET child = INVALID_SOCKET;
  child = (accept)( s, addr, addrlen );
  if( (INVALID_SOCKET!=child) && ! Ressource_Register( CrtDbgType_Socket, 1, (void*) child, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }
  return child;
}}


int dbg_closesocket( SOCKET s, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"closesocket";
  int iRet = EOF;

  if( ! Ressource_PreUnregister( CrtDbgType_Socket, (const void*) s, pFILE, LINE, pFUNCTION ) )
    { _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, 
                          L"%s(0x%08x) will probably crash now...\r\n", 
                          pMethodName, s );
    }

  iRet = (closesocket)( s );

  if( (0==iRet) && ! Ressource_Unregister( CrtDbgType_Socket, (void*) s, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return iRet;
}}

# if !defined( CRTDBG_WS1 )
SOCKET dbg_WSASocket( int af, int type, int prot, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags, 
                        const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"WSAsocket";
  SOCKET s = (WSASocket)( af, type, prot, lpProtocolInfo, g, dwFlags );
  if( (INVALID_SOCKET!=s) && ! Ressource_Register( CrtDbgType_Socket, 1, (void*) s, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }
  return s;
}}


SOCKET dbg_WSAAccept( SOCKET s, struct sockaddr FAR* addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD dwCallbackData, 
                        const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"WSAaccept";
  SOCKET s = INVALID_SOCKET;
  s = (WSAAccept)( s, addr, addrlen, lpfnCondition, dwCallbackData );
  if( (INVALID_SOCKET!=s) && ! Ressource_Register( CrtDbgType_Socket, 1, (void*) s, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }
  return s;
}}


INT dbg_WSALookupServiceBegin( LPWSAQUERYSETW lpqsRestrictions, DWORD dwControlFlags, LPHANDLE lphLookup, 
                        const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"WSALookupServiceBegin";
  int iRes = (WSALookupServiceBegin)( lpqsRestrictions, dwControlFlags, lphLookup );
  if( (0==iRes) && lphLookup && ! Ressource_Register( CrtDbgType_WSAService, 1, (void*) *lphLookup, false, pFILE, LINE, pFUNCTION, NULL, lphLookup ) )
    { _MM_DebugBreak(); }
  return iRes;
}}


INT dbg_WSALookupServiceEnd( HANDLE hLookup, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"WSALookupServiceEnd";
  int iRet = EOF;

  if( ! Ressource_PreUnregister( CrtDbgType_WSAService, (const void*) hLookup, pFILE, LINE, pFUNCTION ) )
    { _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, 
                          L"%s(0x%08x) will probably crash now...\r\n", 
                          pMethodName, hLookup );
    }

  iRet = (WSALookupServiceEnd)( hLookup );

  if( (0==iRet) && ! Ressource_Unregister( CrtDbgType_WSAService, (void*) hLookup, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return iRet;
}}


WSAEVENT dbg_WSACreateEvent( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"WSACreateEvent";
  WSAEVENT Evt = (WSACreateEvent)();
  if( (NULL!=Evt) && ! Ressource_Register( CrtDbgType_WSAEvent, 1, (void*) Evt, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return Evt;
}}


BOOL dbg_WSACloseEvent( WSAEVENT hEvent, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"WSACloseEvent";
  int iRet = EOF;

  if( ! Ressource_PreUnregister( CrtDbgType_WSAEvent, (const void*) hEvent, pFILE, LINE, pFUNCTION ) )
    { _My_CrtDbgReportW_intern( true, _CRT_ASSERT, pFILE, LINE, pFUNCTION, 
                          L"%s(0x%08x) will probably crash now...\r\n", 
                          pMethodName, hEvent );
    }

  iRet = (WSACloseEvent)( hEvent );

  // GH: SUCCESS is TRUE, so we check (0 != iRet) this time
  if( (iRet) && ! Ressource_Unregister( CrtDbgType_WSAEvent, (void*) hEvent, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }

  return iRet;
}}
# endif //!defined( CRTDBG_WS1 )
#endif //!defined( CRTDBG_NO_WS )

/* ===[ CrtDbgType_Registry ] ============================================================== */
/* ===[ Event & Mutex & Process & Thread ] ================================================= */
HANDLE dbg_CreateThread( LPSECURITY_ATTRIBUTES lpsa, DWORD cbStack, LPTHREAD_START_ROUTINE lpStartAddr, LPVOID lpvThreadParam, DWORD fdwCreate, LPDWORD lpIDThread, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION )
{{
  const WCHAR * pMethodName = L"CreateThread";
  HANDLE hThread = NULL;

  hThread = (CreateThread)((lpsa), (cbStack), (lpStartAddr), (lpvThreadParam), (fdwCreate), (lpIDThread));
  if( NULL!=hThread && ! Ressource_Register( CrtDbgType_Thread, 1, (void*) hThread, false, pFILE, LINE, pFUNCTION ) )
    { _MM_DebugBreak(); }
  return hThread;
}}
/* ===[ FindFirstFile ] ==================================================================== */
/* ===[ XXXXXXXXXXXXXXXXXXX ] ============================================================== */





#ifdef __cplusplus
  }
#endif


#endif //defined(_CRTDBG__NO_MICROSOFT)
/*EOF*/
