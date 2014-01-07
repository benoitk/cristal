#include "stdafx.h"
#include "header.h"
#include <windows.h>
#include <stdio.h>
#include <winioctl.h >
#include "System.h"

/*BOOL CSystem::HardResetPanelPC() 
{ 
	SetCleanRebootFlag(); 
	return KernelIoControl(IOCTL_HAL_REBOOT, NULL, 0, NULL, 0, NULL); 
} 
//------------------------------------------------------------------------------
//
// Gets the model information from the device.  The passed in buffer should be
// at least 64 characters in length
//
//------------------------------------------------------------------------------
BOOL CSystem::getModelInformation(TCHAR* buf, UINT bufLength)
{
    BOOL res = TRUE;

    // Clear the buffer
    memset(buf, 0, bufLength * sizeof(TCHAR));

    // Get the model information
    res = ::SystemParametersInfo(SPI_GETOEMINFO, bufLength, buf, 0);

    if(res == FALSE)
    {
        // Failure!! Return error code
        _stprintf(buf, _T("ERR: %d"), ::GetLastError());
    }

    return res;
}

//------------------------------------------------------------------------------
//
// Gets the 10 byte preset id and the 6 byte platform id from the device, and
// returns it as a serial number in form (xxxxxxxxxx-xxx-xxx).  The passed in
// buffer should be at least 20 characters in length.
//
//------------------------------------------------------------------------------
BOOL CSystem::getSerialNumber(TCHAR* buf, UINT bufLength)
{
    const UINT SERIAL_NUM_LEN = 16;
    const UINT PRESET_ID_LEN = 10;
    const UINT PLATFORM_ID_LEN = 6;

    BOOL res = TRUE;
    DWORD dwOutBytes;
    const INT BUF_SIZE = 128;
    byte arrOutBuff[BUF_SIZE];
    byte sn[SERIAL_NUM_LEN];

    // Clear both buffers
    memset(buf, 0, bufLength);
    memset(arrOutBuff, 0, BUF_SIZE);

    // Some devices, like Dell, need the dwSize element of the DEVICE_ID
    // structure to be initialized.
    DEVICE_ID* p = (DEVICE_ID*)arrOutBuff;
    p->dwSize = BUF_SIZE;

    res = ::KernelIoControl(IOCTL_HAL_GET_DEVICEID, 0, 0, arrOutBuff,
	BUF_SIZE, &dwOutBytes);
    if(res)
    {
        int presetIdOffset = p->dwPresetIDOffset;
        int platformIdOffset = p->dwPlatformIDOffset;

        memcpy(&sn[0], &arrOutBuff[presetIdOffset], PRESET_ID_LEN);
        memcpy(&sn[PRESET_ID_LEN], &arrOutBuff[platformIdOffset],
		PLATFORM_ID_LEN);

        _stprintf(buf,
	_T("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X-%02X%02X%02X-%02X%02X%02X%02X%02X%02X%02X"),
            sn[0],sn[1],sn[2],sn[3],sn[4],sn[5],sn[6],sn[7],sn[8],sn[9],
            sn[10],sn[11],sn[12],sn[13],sn[14],sn[15],sn[16],sn[17],sn[18],sn[19]);
    }
    else
    {
        _stprintf(buf, _T("ERR: %d"), ::GetLastError());
    }

    return res;
}

	//Initialise la taille de la mémoire
	/*int nStoragePages = 128; // x4 donne la taille en Ko affecté au stockage.

	HINSTANCE hCoreDll = LoadLibrary(_T("coredll.dll"));
	SetSystemMemoryDivisionProc procSet = (SetSystemMemoryDivisionProc)GetProcAddress(
															hCoreDll, _T("SetSystemMemoryDivision"));

	DWORD dwResult = procSet(nStoragePages);

	//Process result code

	FreeLibrary(hCoreDll);*/