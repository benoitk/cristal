/*****************************************************************************
 File: countof.h
 This module declares a cool _countof() C++ template function / C-Macro
 Taken from Bjarne Stroustrups new book (2010)
 Written down by: 2011-10-01 / Modem Man
*****************************************************************************/
#ifndef __COUNTOF_HELPER_H__
#define __COUNTOF_HELPER_H__

/* _countof helper */
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

#endif /*#def __COUNTOF_HELPER_H__*/
