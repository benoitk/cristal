// Cristal.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "header.h"
#include "wincrypt.h"
#include <windows.h>
#include <stdio.h>

#include <winioctl.h > 

typedef BOOL (__stdcall *GetSystemMemoryDivisionProc)(LPDWORD,LPDWORD,LPDWORD);
typedef DWORD (__stdcall *SetSystemMemoryDivisionProc)(DWORD);

#define DEBUG_S

int az_tmain(int argc, _TCHAR* argv[])
{
	TCHAR szText[MAX_PATH];
	//TCHAR szMessage[260];
	HANDLE hCristalAppOnce = NULL;
	BOOL bReturn;
	CAnalyseur Analyseur;
	CSocketIHM SocketIHM;
	CCarteIO CarteIO;
	CCarteMesure CarteMesure;
	CCarteJbusSlave CarteJbusSlave;
	
	//Initialise la taille de la mémoire
	int nStoragePages = 2048; // x4 donne la taille en Ko affecté au stockage.

	HINSTANCE hCoreDll = LoadLibrary(_T("coredll.dll"));
	SetSystemMemoryDivisionProc procSet = (SetSystemMemoryDivisionProc)GetProcAddress(
															hCoreDll, _T("SetSystemMemoryDivision"));

	DWORD dwResult = procSet(nStoragePages);

	//Process result code

	FreeLibrary(hCoreDll);

	// protection lancement multiple
	hCristalAppOnce = OpenEvent(EVENT_ALL_ACCESS,FALSE,_T("CRISTAL_APP_ONCE"));
	if (hCristalAppOnce)
	{
		CloseHandle(hCristalAppOnce);
		return -1;
	}
	else hCristalAppOnce = CreateEvent(NULL,TRUE,FALSE,_T("CRISTAL_APP_ONCE"));

	_tprintf(_T(" CHARGEMENT CONFIGURATION...\n\n"));

	Analyseur.m_ExternalInterface.SetExternalInterface(&SocketIHM,&CarteIO,&CarteMesure,&CarteJbusSlave);
	SocketIHM.m_ExternalInterface.SetExternalInterface(&SocketIHM,&CarteIO,&CarteMesure,&CarteJbusSlave);
	SocketIHM.SetAccess(TRUE,TRUE);


	// chargement config
	bReturn = bCopyFile(szGetFullPathName(_T("MsgErrorIHM.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) ReadConfigMsgError(SZ_FIC_TEMP);

	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("config.ini"),szText),SZ_FIC_TEMP,FALSE);
 	if (bReturn) bReturn = Analyseur.bReadConfig(SZ_FIC_TEMP);
	if (bReturn) bReturn = Analyseur.bReadCycle(SZ_FIC_TEMP);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("InterfaceIHM.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) bReturn = SocketIHM.bReadConfig(SZ_FIC_TEMP,&Analyseur);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("InterfaceIO.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) bReturn = CarteIO.bReadConfig(SZ_FIC_TEMP,&Analyseur);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("InterfaceMesure.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) bReturn = CarteMesure.bReadConfig(SZ_FIC_TEMP,&Analyseur);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("InterfaceJbusSlave.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) bReturn = CarteJbusSlave.bReadConfig(SZ_FIC_TEMP,&Analyseur);



	_tprintf(_T("****************************************\n"));
	_tprintf(_T("* BILAN DES TESTS CONFIG ANALYSEUR: %s *\n"),bReturn ? _T("OK") : _T("KO"));
	_tprintf(_T("****************************************\n\n"));
	

	TRACE_LOG_MSG(_T("APPLICATION STARTED"));

	TCHAR ch;

	if (bReturn)
	{
		//attente que l'IHM se lance avant de démarer le cycle de 15s
		for(int i=0; i<15; i++) Sleep(1000);

		// lancement des tâche
		/*SocketIHM.hCreateThread();
		while (!SocketIHM.bGetInRunThread()) Sleep(1000);
		CarteIO.hCreateThread();
		while (!CarteIO.bGetInRunThread()) Sleep(1000);
		CarteMesure.hCreateThread();
		while (!CarteMesure.bGetInRunThread()) Sleep(1000);
		CarteJbusSlave.hCreateThread();
		while (!CarteJbusSlave.bGetInRunThread()) Sleep(1000);*/
		/*Analyseur.hCreateThread();*/

		_tprintf(_T("* Appuyer sur la touche <ENTER> pour quitter l'application: %s *\n"),bReturn ? _T("OK") : _T("KO"));

		do 
		{
			Analyseur.SetRemoteControl();
			if (Analyseur.m_ExternalInterface.m_pCarteIO->bGetError() || Analyseur.m_ExternalInterface.m_pCarteJbusSlave->bGetError())
			{
				TRACE_DEBUG_IHM(eError,eCycle,eErrorAppRunThread);
				Analyseur.m_bStatusFailure.bSetVal(1);
			}
			ch = GetKeyState(VK_ESCAPE);//getchar();
			ch |= GetKeyState(VK_RETURN);//getchar();
			Sleep(1000);
		}
		while ((ch & 0x8000) == 0);

		Analyseur.Stop();
		CarteMesure.Stop();
		CarteIO.Stop();
		CarteJbusSlave.Stop();
		SocketIHM.Stop();



#ifndef _WIN32_WCE
		Analyseur.bWriteConfig(szGetFullPathName(_T("configSave.ini"),szText));
		if (bReturn) bReturn = SocketIHM.bWriteConfig(szGetFullPathName(_T("InterfaceIHMSave.ini"),szText));
		if (bReturn) bReturn = CarteIO.bWriteConfig(szGetFullPathName(_T("InterfaceIOSave.ini"),szText));
		if (bReturn) bReturn = CarteMesure.bWriteConfig(szGetFullPathName(_T("InterfaceMesureSave.ini"),szText));
		if (bReturn) bReturn = CarteJbusSlave.bWriteConfig(szGetFullPathName(_T("InterfaceJbusSlaveSave.ini"),szText));
	
		WriteConfigMsgError(szGetFullPathName(_T("MsgErrorIHMSave.ini"),szText));
#endif
	}

	else
	{
		do 
		{
			ch = GetKeyState(VK_ESCAPE);//getchar();
			ch |= GetKeyState(VK_RETURN);//getchar();
			Sleep(1000);
		}
		while ((ch & 0x8000) == 0);
	}

	CloseHandle(hCristalAppOnce);

	//HardResetPanelPC();
	return 0;
}



