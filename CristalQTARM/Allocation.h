#pragma once
#include <windows.h>
class CAllocation
{
public:
	void *operator new[](size_t size)
	{
		OutputDebugString(_T("NEW[] !/n"));
		void *p = VirtualAlloc(0, size, MEM_RESERVE, PAGE_NOACCESS);
		p = VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE);
		return p;
	};

	void *operator new(size_t size)
	{
		OutputDebugString(_T("NEW !/n"));

		 void *p = VirtualAlloc(0, size, MEM_RESERVE, PAGE_NOACCESS);
		p = VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE);
		return p;
	};

	void operator delete[](void *ptr)
	{
		VirtualFree(ptr, 0, MEM_RELEASE);
	};

	void operator delete[](void *ptr, size_t)
	{
		VirtualFree(ptr, sizeof(size_t), MEM_RELEASE);
	 
	};

	void operator delete(void *ptr)
	{
		VirtualFree(ptr, 0, MEM_RELEASE);
	 
	};

	void operator delete(void *ptr, size_t)
	{
		VirtualFree(ptr, sizeof(size_t), MEM_RELEASE);
	 
	};
	CAllocation(void);
public:
	~CAllocation(void);
};
