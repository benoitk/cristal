#ifndef _MY_CRTDBG_H_
#define _MY_CRTDBG_H_

/***************************************************************************
 * CFCU ("cheap for commercial use") LICENSE NOTE!                         *
 ***************************************************************************
 * ANY USE OF THIS FILE REQUIRES TO ACCEPT THE ATTACHED LICENSE AGREEMENT. *
 * BY USING THIS FILE, YOU AUTOMATICALLY (IMPLICIT) ACCCEPT THE AGREEMENT. *
 * FOR THE LICENSE AGREEMENT IN DETAIL, SEE THE COMPANION FILES.           *
 * (c) 2012-April-16 Maik Reiss, Germany. <mailto:modem-man@gmx.net>       *
 ***************************************************************************/
#if !defined( CRTDBG_NO_WS ) && !defined( CRTDBG_WS1 )
#  include <winsock2.h> // I also like to boundcheck winsock
#elif !defined( CRTDBG_NO_WS ) && defined( CRTDBG_WS1 )
#  include <winsock.h>
#endif //!defined( CRTDBG_NO_WS ) && !defined( CRTDBG_WS1 )

#include <windows.h> // whole winapi must be known
#include <stdio.h>   // FILE* must be known

#if defined( _DEBUG )
/* ======================================================================= */
/* ==   DEBUG DEFINED BLOCK                                             == */
/* ==   DEBUG DEFINED BLOCK                                             == */
/* ==   DEBUG DEFINED BLOCK                                             == */
/* ======================================================================= */
#if defined( _WIN32_WCE )
#  define _INC_ALTCECRT // prevent loading of altcecrt.h file content (crazy!) because this makes some collisions of empty/dummy _CrtDbgxxxx funcs
#  include <altcecrt.h>
#undef _CRT_ERRCNT            // ---
#undef _CRTDBG_INVALID_HFILE  // -
#undef _CRTDBG_HFILE_ERROR    // -  since altcecrt is somehow included before us, some
#undef _CRTDBG_FILE_STDOUT    // -  collisions must be removed anyway
#undef _CRTDBG_FILE_STDERR    // - 
#undef _CrtDbgBreak           // ---
#endif
/* ================================================================= *
 * PART A)                                                           *
 * The Interface of _CrtDbgXxx Functions as inspired by MicroSoft.   *
 *                                                                   *
 * ================================================================= */
#ifndef _CRTDBG_ALLOC_MEM_DF
#define _CRTDBG__NO_MICROSOFT // whit this define, the implementation knows, we are using my code, not the one from M$
#define _CRTDBG_REPORT_FLAG         -1    /* Query bitflag status */
#define _CRTDBG_ALLOC_MEM_DF        0x01  /* Turn on debug allocation */
#define _CRTDBG_DELAY_FREE_MEM_DF   0x02  /* Don't actually free memory */
#define _CRTDBG_CHECK_ALWAYS_DF     0x04  /* Check heap every alloc/dealloc */
#define _CRTDBG_RESERVED_DF         0x08  /* Reserved - do not use */
#define _CRTDBG_CHECK_CRT_DF        0x10  /* Leak check/diff CRT blocks */
#define _CRTDBG_LEAK_CHECK_DF       0x20  /* Leak check at program exit */
/* begin: MM extensions */
#define _CRTDBG_MM_BOUNDSCHECK      0x100  /* Check Buffer Overrung / underrun signatures */
#define _CRTDBG_MM_CHATTY_ALLOCFREE 0x200  /* Check Buffer Overrung / underrun signatures */
/* end: MM extensions */
#define _CRTDBG_CHECK_EVERY_16_DF   0x00100000  /* check heap every 16 heap ops */
#define _CRTDBG_CHECK_EVERY_128_DF  0x00800000  /* check heap every 128 heap ops */
#define _CRTDBG_CHECK_EVERY_1024_DF 0x04000000  /* check heap every 1024 heap ops */
#define _CRT_WARN           0
#define _CRT_ERROR          1
#define _CRT_ASSERT         2
#define _CRT_REPORT         3 /* new, internal use by Modem Man's Port only */
#define _CRT_ERRCNT         4
#define _CRTDBG_MODE_FILE      0x1
#define _CRTDBG_MODE_DEBUG     0x2
#define _CRTDBG_MODE_WNDW      0x4
#define _CRTDBG_REPORT_MODE    -1
#define _CRTDBG_INVALID_HFILE (-1)
#define _CRTDBG_HFILE_ERROR   (_CRTDBG_INVALID_HFILE-2) // just for reporting errors
#define _CRTDBG_FILE_STDOUT   (_CRTDBG_INVALID_HFILE-4)
#define _CRTDBG_FILE_STDERR   (_CRTDBG_INVALID_HFILE-5)
//#define _CRTDBG_REPORT_FILE (_CRTDBG_INVALID_HFILE-6)
#endif


#if defined(_DEBUG)
# define dbg_WIDEN2(x) L ## x
# define dbg_WIDEN(x) dbg_WIDEN2(x)
# define __dbg_WFILE__ dbg_WIDEN(__FILE__)
# define __dbg_WFUNC__ dbg_WIDEN(__FUNCTION__)
#endif

#ifdef __cplusplus
  extern "C" {
#endif

#if defined(_CRTDBG__NO_MICROSOFT)
#pragma message( "To be cmpleted: a lot of functions..." )
# define _CrtSetDbgFlag(NewFlag)                     _My_CrtSetDbgFlag(NewFlag)
# define _CrtSetReportMode( reportType, reportMode ) _My_CrtSetReportMode((reportType),(reportMode))
# define _CrtSetReportFile( reportType, reportFile ) _My_CrtSetReportFile((reportType),(reportFile))
//# define _CrtDumpMemoryLeaks                         _My_CrtDumpMemoryLeaks for evc4 ?
# define _CrtDumpMemoryLeaks(...)                    _My_CrtDumpMemoryLeaks3( __dbg_WFILE__, __LINE__, __dbg_WFUNC__, __VA_ARGS__ )
# define _CrtDbgReport                               _My_CrtDbgReport
# define _CrtDbgReportW                              _My_CrtDbgReportW
# define _CrtCheckMemory                             _My_CrtCheckMemory
# define _CrtDbgBreak                                DebugBreak
# define _CrtMemDumpAllObjectsSince(memstate)        _My_CrtMemDumpAllObjectsSince(memstate)

#endif

struct _CrtMemState;
int    _My_CrtSetDbgFlag( int NewFlag );
int    _My_CrtSetReportMode( int reportType, int reportMode );
HANDLE _My_CrtSetReportFile( int reportType, HANDLE reportFile );
int    _My_CrtDbgReport(  int reportType, const char    *filename, int linenumber, const char    *moduleName, const char    *format, ... );
int    _My_CrtDbgReportW( int reportType, const wchar_t *filename, int linenumber, const wchar_t *moduleName, const wchar_t *format, ... );
int    _My_CrtDumpMemoryLeaks(void);
int    _My_CrtDumpMemoryLeaks2( BOOL OnFinalClose, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
int    _My_CrtDumpMemoryLeaks3( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION, ... );
int    _My_CrtCheckMemory(void);
void   _My_CrtMemDumpAllObjectsSince( const _CrtMemState *state );

/* Asserts */
/* We use double-not (!!) below to ensure that any overloaded operators used to evaluate expr do not end up at operator || */
#define _ASSERT_EXPR(expr, msg) \
        (void) ((!!(expr)) || \
                (1 != _My_CrtDbgReportW(_CRT_ASSERT, __dbg_WFILE__, __LINE__, NULL, msg)) || \
                (_CrtDbgBreak(), 0))

#ifndef _ASSERT
#define _ASSERT(expr)   _ASSERT_EXPR((expr), NULL)
#endif

#ifndef _ASSERTE
#define _ASSERTE(expr)  _ASSERT_EXPR((expr), dbg_WIDEN(#expr))
#endif

// todo: _RPT, and _RPTF 

#ifdef __cplusplus
  }
#endif




/* ================================================================= *
 * PART B)                                                           *
 * The Interface of watched APIs                                     *
 * Here, we define which Win32 API is controlled. We may add more.   *
 *                                                                   *
 * ================================================================= */
#ifdef __cplusplus
  extern "C" {
#endif

#if defined(_DEBUG)
/* ========================================================================================= */
/* ===[ CrtDbgType_HeapMalloc ] ============================================================ */
/* ========================================================================================= */
# define malloc(s)    dbg_malloc( (s),     __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define calloc(s,n)  dbg_calloc( (s),(n), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define realloc(a,s) dbg_realloc((a),(s), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define free(a)      dbg_free(   (a),     __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define strdup(s)    dbg_strdupA((s),     __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define _strdup(s)   dbg_strdupA((s),     __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define _wcsdup(s)   dbg_strdupW((s),     __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
void* dbg_malloc( size_t size,                    const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
void* dbg_calloc( size_t num, size_t size,        const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
void* dbg_realloc( void* oldaddr, size_t newsize, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
void  dbg_free(   void *ptr,                      const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
char    *dbg_strdupA( const char    *ptr,         const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
wchar_t *dbg_strdupW( const wchar_t *ptr,         const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
// free needs to be called for pointers allocated by _tempnam() and _wtempnam(), but not on tmpnam() and wtmpnam()
# define _tempnam(dir8,pfx8)   dbg_tempnam( (dir8), (pfx8), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define _wtempnam(dirW,pfxW)  dbg_wtempnam((dirW), (pfxW), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
char    *dbg_tempnam(  const char    *dir, const char    *prefix, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
wchar_t *dbg_wtempnam( const wchar_t *dir, const wchar_t *prefix, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );

/* ========================================================================================= */
/* ===[ CrtDbgType_HeapNew ] =============================================================== */
/* ========================================================================================= */

#ifdef __cplusplus
  }
#endif

#ifdef __cplusplus
  #include <new>
  #if !defined(_PNH)
    #define _PNH _dbg_PNH
    #define set_new_handler(foo) _dbg_set_new_handler(foo)
  #endif
  typedef void (__cdecl * _dbg_PNH)(void);
  #define _PNH_DEFINED
  _dbg_PNH _dbg_set_new_handler( _dbg_PNH pNewHandler );
  
  // use the "placement" version of new
  void * operator new    (size_t size, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
  void * operator new[]  (size_t size, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
  /* There is no placement delete expression. It is not possible to call any placement operator delete function using a delete expression.
     The placement delete functions are called from placement new expressions. In particular, they are called if the constructor of the object 
     throws an exception. In such a circumstance, in order to ensure that the program does not incur a memory leak, the placement delete 
     functions are called. A placement new expression first calls the placement operator new function, then calls the constructor of the object 
     upon the raw storage returned from the allocator function. If the constructor throws an exception, it is necessary to deallocate that 
     storage before propagating the exception back to the code that executed the placement new expression, and that is the purpose of the 
     placement delete functions */  
  void operator delete   (void * ptr, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
  void operator delete[] (void * ptr, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
  void operator delete   (void * ptr );
  void operator delete[] (void * ptr );
  #if !defined( MM_CRTDBG_CPP ) // do not define this, if included from my own cpp. Only from user code
    #define DEBUG_NEW_PLACEMENT new( __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
    #define new DEBUG_NEW_PLACEMENT
    //notworking, but may have a chance: #define delete(x) operator cout& UnregisterNew( x, __dbg_WFILE__, __LINE__, __dbg_WFUNC__), delete(x)
  #endif
#endif // def __cplusplus

#ifdef __cplusplus
  extern "C" {
#endif

/* ========================================================================================= */
/* ===[ CrtDbgType_Win32File ] ============================================================= */
/* ========================================================================================= */
#ifdef CreateFile
#  undef CreateFile
#  define CreateFile(Nam,Acc,Shr,SA,Crea,Flg,tpl)   dbg_CreateFileW((Nam),(Acc),(Shr),(SA),(Crea),(Flg),(tpl), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ );
   HANDLE dbg_CreateFileW( LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
                           const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
#endif

#if defined( _WIN32_WCE )
#  undef CreateFileForMapping
#  define CreateFileForMapping(Nam,Acc,Shr,SA,Crea,Flg,tpl)   dbg_CreateFileForMapping((Nam),(Acc),(Shr),(SA),(Crea),(Flg),(tpl), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ );
HANDLE dbg_CreateFileForMapping( LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, 
                           DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile,
                           const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
#endif // defined( _WIN32_WCE )

// If you call CreateFileMapping with a handle from CreateFileForMapping and it fails for any reason, the handle is closed.
#ifdef CreateFileMapping
#  undef CreateFileMapping
#  define CreateFileMapping(Hdl,SA,Flg,SizH,SizL,Nam)  dbg_CreateFileMapping((Hdl),(SA),(Flg),(SizH),(SizL),(Nam), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ );
   HANDLE dbg_CreateFileMapping( HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, 
                           DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCWSTR lpName,
                           const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
#endif

// Creating a file-mapping object creates the potential for mapping a view of the file but does not map the view. 
// The MapViewOfFile function maps a view of a file into the address space of a process. 
// To fully close a file-mapping object, an application must unmap all mapped views of the file-mapping object by calling UnmapViewOfFile, 
// and close the file-mapping object handle by calling CloseHandle. The order in which these functions are called does not matter.
// The call to UnmapViewOfFile is necessary because mapped views of a file-mapping object maintain internal open handles to the object, 
// and a file-mapping object will not close until all open handles to it are closed.
#define MapViewOfFile(hdl,Acc,OffH,OffL,Siz)  dbg_MapViewOfFile( (hdl),(Acc),(OffH),(OffL),(Siz), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ );
void *  dbg_MapViewOfFile( HANDLE hFileMappingObject, DWORD dwDesiredAccess, 
                           DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, DWORD dwNumberOfBytesToMap, 
                           const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
//Although an application may close the file handle used to create a file-mapping object, the system holds the corresponding file open until the last view of the file is unmapped.
#define UnmapViewOfFile(ptr) dbg_UnmapViewOfFile((ptr), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ );
BOOL dbg_UnmapViewOfFile( const void *lpBaseAddress, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );


#define CloseHandle(H)  dbg_CloseHandle((H), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ );
BOOL dbg_CloseHandle( HANDLE Handle, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
#define DuplicateHandle(SrcProcH,H,DstProcH,pResultH,dwIgnore,bFalse,opt)  dbg_DuplicateHandle((SrcProcH),(H),(DstProcH),(pResultH),(dwIgnore),(bFalse),(opt), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ );
BOOL dbg_DuplicateHandle(  HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
                           LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions,
                           const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );

/* ========================================================================================= */
/* ===[ CrtDbgType_Stream ] ================================================================ */
/* ========================================================================================= */
/*
// as far as I can see, there is no leakage way to _dup/_dup2. But if anybody knows details ...
int _fileno( FILE *Stream );
int _dup( int fildescr );
int _dup2( int fildescr1, int fildescr2 );
int fcntl( int fildescr, int code, int fildescr2 );
// no posix: int dup( int fd );
// no posix: int fcntl( int fildescr, F_DUPFD, 0);
// no posix: int (close(fildescr2), fcntl( fildescr, F_DUPFD, fildescr2 ));
// no posix: FILE *fdopen(int fd, const char *modus);
*/
#define _fcloseall()                                       dbg_fcloseall(                                        __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define fclose( StreamH )                                  dbg_fclose( (StreamH),                                __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define fopen(  Name8,Mode8)                               dbg_fopen(                 (Name8),(Mode8),           __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define _wfopen(NameW,ModeW)                               dbg_wfopen(                (NameW),(ModeW),           __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define fopen_s( ppStream, Name8, Mode8 )                dbg_fopen_s(    (ppStream),(Name8),(mode8),           __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define _wfopen_s( ppStream, NameW, ModeW )                dbg_wfopen_s(   (ppStream),(NameW),(modeW),           __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define freopen(  Name8, Mode8, StreamH)                   dbg_freopen(               (Name8),(Mode8),(StreamH), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define _wfreopen(NameW, ModeW, StreamH)                   dbg_wfreopen(              (NameW),(ModeW),(StreamH), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define freopen_s( ppStream, Name8, mode8, streamH )     dbg_freopen_s(  (ppStream),(Name8),(mode8),(streamH), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#define _wfreopen_s( ppStream, NameW, modeW, streamH )     dbg_wfreopen_s( (ppStream),(NameW),(modeW),(streamH), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )

int   dbg_fcloseall(                                                                                   const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION ); // _fcloseall returns the total number of streams closed, returns EOF to indicate an error.
int   dbg_fclose( FILE* Stream,                                                                        const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION ); // fclose returns 0 if the stream is successfully closed, returns EOF to indicate an error.
FILE *dbg_fopen(                         const char    *filename8, const char    *mode8,               const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
FILE *dbg_wfopen(                        const wchar_t *filenameW, const wchar_t *modeW,               const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
FILE *dbg_freopen(                       const char    *filename8, const char    *mode8, FILE *stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
FILE *dbg_wfreopen(                      const wchar_t *filenameW, const wchar_t *modeW, FILE *stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
#if !defined( _WIN32_WCE ) || (defined( _WIN32_WCE ) && ( _WIN32_WCE >= 0x500 ))
// _s secure API 1st avail under CE5 and higher
errno_t dbg_fopen_s(    FILE** ppStream, const char    *filename8, const char    *mode8,               const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );  // EINVAL, 0 on okay
errno_t dbg_wfopen_s(   FILE** ppStream, const wchar_t *filenameW, const wchar_t *modeW,               const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );  // EINVAL, 0 on okay
errno_t dbg_freopen_s(  FILE** ppStream, const char    *filename8, const char    *mode8, FILE *stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
errno_t dbg_wfreopen_s( FILE** ppStream, const wchar_t *filenameW, const wchar_t *modeW, FILE *stream, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
#endif

/* ========================================================================================= */
/* ===[ CrtDbgType_WSAStart / CrtDbgType_Socket / ... ] ==================================== */
/* ========================================================================================= */
#if !defined( CRTDBG_NO_WS )
# define  WSAStartup(ver,ptr)   dbg_WSAStartup((ver),(ptr),     __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define  WSACleanup()          dbg_WSACleanup(                 __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define  socket(af,type,prot)  dbg_socket((af),(type),(prot),  __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define  accept(s,pAddr,pAlen) dbg_accept((s),(pAddr),(pAlen), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
# define  closesocket(s)        dbg_closesocket((s),            __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
  int     dbg_WSAStartup( WORD Ver, LPWSADATA pWSA, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
  int     dbg_WSACleanup( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
  SOCKET  dbg_socket( int af, int type, int prot, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
  SOCKET  dbg_accept( SOCKET s, struct sockaddr FAR* addr, int FAR* addrlen, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
  int     dbg_closesocket( SOCKET s, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );

# if !defined( CRTDBG_WS1 )
#   define   WSAsocket(af,type,prot,pPI,g,Flg)   dbg_WSAsocket((af),(type),(prot),(pPI),(g),(Flg), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#   define   WSAaccept(s,pAddr,pAlen,foo,cb)     dbg_WSAaccept((s),(pAddr),(pAlen),(foo),(cb),     __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#   define   WSALookupServiceBeginW(qs,Flg,pHnd) dbg_WSALookupServiceBegin((qs),(Flg),(pHnd),      __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#   define   WSALookupServiceEnd(Hnd)            dbg_WSALookupServiceEnd((Hnd),                    __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#   define   WSACreateEvent()                    dbg_WSACreateEvent(                               __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
#   define   WSACloseEvent(h)                    dbg_WSACloseEvent((h),                            __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
    SOCKET   dbg_WSASocket( int af, int type, int prot, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
    SOCKET   dbg_WSAAccept( SOCKET s, struct sockaddr FAR* addr, LPINT addrlen, LPCONDITIONPROC lpfnCondition, DWORD dwCallbackData, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
    INT      dbg_WSALookupServiceBegin( LPWSAQUERYSETW lpqsRestrictions, DWORD dwControlFlags, LPHANDLE lphLookup, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
    INT      dbg_WSALookupServiceEnd( HANDLE hLookup, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
    WSAEVENT dbg_WSACreateEvent( const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
    BOOL     dbg_WSACloseEvent( WSAEVENT hEvent, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
# endif //!defined( CRTDBG_WS1 )
#endif //!defined( CRTDBG_NO_WS )
/* ========================================================================================= */
/* ===[ CrtDbgType_Registry ] ============================================================== */
/* ========================================================================================= */

/* ========================================================================================= */
/* ===[ Event & Mutex & Process & Thread ] ================================================= */
/* ========================================================================================= */
#define CreateThread(pSecurAtt,nStack,pFunc,pParam,dwCreatFlg,pTID)  dbg_CreateThread((pSecurAtt),(nStack),(pFunc),(pParam),(dwCreatFlg),(pTID), __dbg_WFILE__, __LINE__, __dbg_WFUNC__ )
HANDLE dbg_CreateThread( LPSECURITY_ATTRIBUTES lpsa, DWORD cbStack, LPTHREAD_START_ROUTINE lpStartAddr, LPVOID lpvThreadParam, DWORD fdwCreate, LPDWORD lpIDThread, const WCHAR * pFILE, unsigned LINE, const WCHAR * pFUNCTION );
// Close is just CloseHandle()
/* ========================================================================================= */
/* ===[ FindFirstFile ] ==================================================================== */
/* ========================================================================================= */
/* ========================================================================================= */
/* ===[ XXXXXXXXXXXXXXXXXXX ] ============================================================== */
/* ========================================================================================= */
/* ========================================================================================= */
#endif // defined(_DEBUG)

#ifdef __cplusplus
  }
#endif


/* ======================================================================= */
/* ==   DEBUG DEFINED BLOCK                                             == */
/* ==   DEBUG DEFINED BLOCK                                             == */
/* ==   DEBUG DEFINED BLOCK                                             == */
/* ======================================================================= */
#else // if defined( _DEBUG )
/* ======================================================================= */
/* ==   DEBUG NOT DEFINED BLOCK                                         == */
/* ==   DEBUG NOT DEFINED BLOCK                                         == */
/* ==   DEBUG NOT DEFINED BLOCK                                         == */
/* ======================================================================= */
/*
-------------------
*/
# define _CrtSetDbgFlag(NewFlag)                     ((int)0)
# define _CrtSetReportMode( reportType, reportMode ) ((int)0)
# define _CrtSetReportFile( reportType, reportFile ) ((_HFILE)0)
# define _CrtDumpMemoryLeaks(...)                    ((int)0)
# define _CrtDbgReport                               ((int)0)
# define _CrtDbgReportW                              ((int)0)
# define _CrtCheckMemory()                           ((int)1)
# define _CrtDbgBreak()                              ((void)0)
# define _CrtMemDumpAllObjectsSince(memstate)        ((void)0)
/* --- not yet implemented for DEBUG build, but dummy for RELEASE --- */
/* --- PLEASE BE AWARE: I'll probably NOT implement all of them!  --- */
# define _CrtSetReportHook(f)                        ((_CRT_REPORT_HOOK)0)
# define _CrtGetReportHook()                         ((_CRT_REPORT_HOOK)0)
# define _CrtSetReportHook2(t, f)                    ((int)0)
# define _CrtSetReportHookW2(t, f)                   ((int)0)
# define _CrtSetBreakAlloc(a)                        ((long)0)
# define _CrtSetAllocHook(f)                         ((_CRT_ALLOC_HOOK)0)
# define _CrtGetAllocHook()                          ((_CRT_ALLOC_HOOK)0)
# define _CrtDoForAllClientObjects(f, c)             ((void)0)
# define _CrtIsValidPointer(p, n, r)                 ((int)1)
# define _CrtIsValidHeapPointer(p)                   ((int)1)
# define _CrtIsMemoryBlock(p, t, r, f, l)            ((int)1)
# define _CrtReportBlockType(p)                      ((int)-1)
# define _CrtSetDumpClient(f)                        ((_CRT_DUMP_CLIENT)0)
# define _CrtGetDumpClient()                         ((_CRT_DUMP_CLIENT)0)
# define _CrtMemCheckpoint(s)                        ((void)0)
# define _CrtMemDifference(s1, s2, s3)               ((int)0)
# define _CrtMemDumpAllObjectsSince(s)               ((void)0)
# define _CrtMemDumpStatistics(s)                    ((void)0)
# define _CrtSetDebugFillThreshold(t)                ((size_t)0)
# define _CrtSetCheckCount(f)                        ((int)0)
# define _CrtGetCheckCount()                         ((int)0)
/* ======================================================================= */
/* ==   DEBUG NOT DEFINED BLOCK                                         == */
/* ==   DEBUG NOT DEFINED BLOCK                                         == */
/* ==   DEBUG NOT DEFINED BLOCK                                         == */
/* ======================================================================= */
#endif // if defined( _DEBUG )

#endif // _MY_CRTDBG_H_