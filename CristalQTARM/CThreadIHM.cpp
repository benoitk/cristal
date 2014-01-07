#include <QtGui/QApplication>
#include <QFile>
 //#include <QDebug>
//#include <QFontDatabase>
#include <QTranslator>
#include <QLocale>
#include <QLibraryInfo>
#include "header.h"
#include "CWinMainControler.h"
#include "CThreadIHM.h"

CThreadIHM::CThreadIHM(int argc, char** argv, CListStream* argAnalyseur,CCarteIO* argCarteIO,CCarteMesure* argCarteMesure, CSocketIHM* argInterfaceIHM)
{
	m_Analyseur = argAnalyseur;
	m_CarteIO = argCarteIO;
	m_CarteMesure = argCarteMesure;
	m_InterfaceIHM = argInterfaceIHM;
	m_argc = argc;
	m_argv = argv;
	m_bInRunThread = false;
}

CThreadIHM::~CThreadIHM(void)
{
}

void CThreadIHM::run(){
	
	QApplication a(m_argc, m_argv);
		
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
	
	CWinMainControler* pControler= new CWinMainControler(m_Analyseur, m_CarteIO,m_CarteMesure, m_InterfaceIHM);
	m_bInRunThread = true;
	
	pControler->execControler();
	a.exec();

	delete pControler;
}
