#include <QtGui/QApplication>
#include <QFile>
 //#include <QDebug>
//#include <QFontDatabase>
#include <QTranslator>
#include <QLocale>
#include <QLibraryInfo>
#include "CWinMainControler.h"
#include "stdafx.h"
#include "header.h"
#include "wincrypt.h"
#include <windows.h>
#include <stdio.h>
#include <winioctl.h > 

//#include "CThreadIHM.h"
//typedef BOOL (__stdcall *GetSystemMemoryDivisionProc)(LPDWORD,LPDWORD,LPDWORD);
//typedef DWORD (__stdcall *SetSystemMemoryDivisionProc)(DWORD);


int main(int argc, char *argv[])
{

	TCHAR szText[MAX_PATH];
	//TCHAR szMessage[260];
	//HANDLE hCristalAppOnce = NULL;
	BOOL bReturn;
	CAnalyseur* pAnalyseur = new CAnalyseur();
	CSocketIHM* pSocketIHM = new CSocketIHM();
	CCarteIO* pCarteIO = new CCarteIO();
    CCarteMesure* pCarteMesure = new CCarteMesure();
	CCarteJbusSlave* pCarteJbusSlave = new CCarteJbusSlave();
	//CThreadIHM* pThreadIhm = new CThreadIHM(argc, argv, pAnalyseur, pCarteIO, pCarteMesure, pSocketIHM);
	
	//Initialise la taille de la mémoire
	//int nStoragePages = 128; // x4 donne la taille en Ko affecté au stockage.

	//HINSTANCE hCoreDll = LoadLibrary(_T("coredll.dll"));
	//SetSystemMemoryDivisionProc procSet = (SetSystemMemoryDivisionProc)GetProcAddress(
	//														hCoreDll, _T("SetSystemMemoryDivision"));

	//DWORD dwResult = procSet(nStoragePages);

	////Process result code

	//FreeLibrary(hCoreDll);

	// protection lancement multiple
	/*hCristalAppOnce = OpenEvent(EVENT_ALL_ACCESS,FALSE,_T("CRISTAL_APP_ONCE"));
	if (hCristalAppOnce)cd 
	{
		CloseHandle(hCristalAppOnce);
		return -1;
	}
	else hCristalAppOnce = CreateEvent(NULL,TRUE,FALSE,_T("CRISTAL_APP_ONCE"));*/

	//DWORD size = 10*2*1024*1024; // (or more) (2*1024*1024)=2Mo

	//void *p = VirtualAlloc(0, size, MEM_RESERVE, PAGE_NOACCESS);
	//p = VirtualAlloc(p, size, MEM_COMMIT, PAGE_READWRITE);

	_tprintf(_T(" CHARGEMENT CONFIGURATION...\n\n"));

	pAnalyseur->m_ExternalInterface.SetExternalInterface(pSocketIHM,pCarteIO,pCarteMesure,pCarteJbusSlave);
	pSocketIHM->m_ExternalInterface.SetExternalInterface(pSocketIHM,pCarteIO,pCarteMesure,pCarteJbusSlave);
	pSocketIHM->SetAccess(TRUE,TRUE);
	
	// chargement config
	bReturn = bCopyFile(szGetFullPathName(_T("MsgErrorIHM.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) ReadConfigMsgError(SZ_FIC_TEMP);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("config.ini"),szText),SZ_FIC_TEMP,FALSE);
 	if (bReturn) bReturn = pAnalyseur->bReadConfig(SZ_FIC_TEMP);
	if (bReturn) bReturn = pAnalyseur->bReadCycle(SZ_FIC_TEMP);
	//if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("InterfaceIHM.ini"),szText),SZ_FIC_TEMP,FALSE);
	//if (bReturn) bReturn = pSocketIHM->bReadConfig(SZ_FIC_TEMP,pAnalyseur);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("InterfaceIO.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) bReturn = pCarteIO->bReadConfig(SZ_FIC_TEMP,pAnalyseur);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("InterfaceMesure.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) bReturn = pCarteMesure->bReadConfig(SZ_FIC_TEMP,pAnalyseur);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(_T("InterfaceJbusSlave.ini"),szText),SZ_FIC_TEMP,FALSE);
	if (bReturn) bReturn = pCarteJbusSlave->bReadConfig(SZ_FIC_TEMP,pAnalyseur);

	_tprintf(_T("****************************************\n"));
	_tprintf(_T("* BILAN DES TESTS CONFIG ANALYSEUR: %s *\n"),bReturn ? _T("OK") : _T("KO"));
	_tprintf(_T("****************************************\n\n"));

	TRACE_LOG_MSG(_T("APPLICATION STARTED"));
	
	TCHAR ch;
	if (bReturn)
	{
		//while (!pSocketIHM->bGetInRunThread()) Sleep(1000);
		//TRACE_LOG_MSG(_T("SocketIHM STARTED"));*/
        pCarteIO->setStackSize(64000);
		pCarteIO->start();
		while (!pCarteIO->bGetInRunThread()) Sleep(1000);
		TRACE_LOG_MSG(_T("CarteIO STARTED"));
           
        pCarteMesure->setStackSize(64000);
        pCarteMesure->start();
		while (!pCarteMesure->bGetInRunThread()) Sleep(1000);
		TRACE_LOG_MSG(_T("CarteMesure STARTED"));
     
        pCarteJbusSlave->setStackSize(64000);
		pCarteJbusSlave->start();
		while (!pCarteJbusSlave->bGetInRunThread()) Sleep(1000);
		TRACE_LOG_MSG(_T("CarteJbusSlave STARTED"));

        pAnalyseur->setStackSize(64000);
  		pAnalyseur->start();
		TRACE_LOG_MSG(_T("Analyseur STARTED"));
		
		/*pThreadIhm->setStackSize(64000);
		pThreadIhm->start();
		while (!pThreadIhm->bGetInRunThread()) Sleep(1000);
		TRACE_LOG_MSG(_T("pThreadIhm STARTED"));
		while(pThreadIhm->isRunning()) Sleep(5000);*/
		
		_tprintf(_T("* Appuyer sur la touche <ENTER> pour quitter l'application: %s *\n"),bReturn ? _T("OK") : _T("KO"));
		
		QApplication a(argc, argv);
		
		QTranslator qtTranslator;
		if(qtTranslator.load("cristalqtarm_en.qm"))
				qDebug() << "Fichier anglais chargé" ;
        else if(qtTranslator.load("cristalqtarm_ru.qm"))
				qDebug() << "Fichier anglais chargé" ;
		a.installTranslator(&qtTranslator);

		//chargement stylesheet
#ifdef RES_640_480
		QFile file("cristalX86.qss");
#else
		QFile file("cristal.qss");
#endif
		file.open(QFile::ReadOnly);
		a.setStyleSheet(QLatin1String(file.readAll()));
		
		CWinMainControler* pControler= new CWinMainControler(pAnalyseur, pCarteIO,pCarteMesure, pSocketIHM);
		pControler->execControler();
		
		a.exec();
			
		_tprintf(_T("* Arrêt des process ..."));
		pAnalyseur->Stop();
        delete pAnalyseur;
		_tprintf(_T("."));
		pCarteMesure->Stop();
        delete pCarteMesure;
		_tprintf(_T("."));
		pCarteIO->Stop();
        delete pCarteIO;
		_tprintf(_T("."));
		pCarteJbusSlave->Stop();
        delete pCarteJbusSlave;
		_tprintf(_T("."));
		pSocketIHM->Stop();
        delete pSocketIHM;
		_tprintf(_T("."));
		
		

#ifndef _WIN32_WCE
		pAnalyseur->bWriteConfig(szGetFullPathName(_T("configSave.ini"),szText));
		if (bReturn) bReturn = pSocketIHM->bWriteConfig(szGetFullPathName(_T("InterfaceIHMSave.ini"),szText));
		if (bReturn) bReturn = pCarteIO->bWriteConfig(szGetFullPathName(_T("InterfaceIOSave.ini"),szText));
		if (bReturn) bReturn = pCarteMesure->bWriteConfig(szGetFullPathName(_T("InterfaceMesureSave.ini"),szText));
		if (bReturn) bReturn = pCarteJbusSlave->bWriteConfig(szGetFullPathName(_T("InterfaceJbusSlaveSave.ini"),szText));
	
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
	_tprintf(_T("."));
	
//	CloseHandle(hCristalAppOnce);
	_tprintf(_T("."));
	
	return 0;
}
