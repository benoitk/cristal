#include "CWinMainControler.h"
#include "CWinExternalCardControler.h"
#include "CWinEVPompeControler.h"
#include "CDialogRestauration.h"
#include "CDialogInfo.h"
#include "CDialogMessage.h"
#include "CDialogCopyFiles.h"
#include "CDialogAlarm.h"
#include "CSupervision.h"
#include "CWinMainView.h"
#include "CWinMainModel.h"
#include "CWinElecTestControler.h"
#include "CDialogStopCycle.h"
#include "CUserSession.h"
#include "CWinStreamControler.h"
#include "CWinMaintenanceControler.h"
#include "CWinSchedulerControler.h"
#include "CDialogPassword.h"
#include "CDialogPaveNum.h"
#include "CDialogResultatEtalon.h"
#include "CDialogValEtalon.h"

#include "header_qt.h"
CWinMainControler::CWinMainControler(CListStream* argAnalyseur,CCarteIO* argCarteIO,CCarteMesure* argCarteMesure, CSocketIHM* argInterfaceIHM)
    :m_CurrentGraphPage(0)
{
	qDebug() << "#### CWinMainControler::CWinMainControler" << endl;
	
	m_pSupervision = new CSupervision();
	m_pSupervision->setAnalyseur((CAnalyseur*)argAnalyseur);
	m_pSupervision->setCarteMesure(argCarteMesure);
	m_pSupervision->setCarteIO(argCarteIO);
	m_pSupervision->setInterfaceIHM(argInterfaceIHM);

	//Fenêtre alarme
	m_pDialogAlarm = new CDialogAlarm(m_pSupervision);
   
    //Fenêtre principale
	m_pView  = new CWinMainView(this);
	m_pModel = new CWinMainModel(m_pSupervision, m_pView);
	m_pView->setModel(m_pModel);

    //Construction des objets avant pour plus de fluidité  
	CWinElecTestControler::getInstance(this);
    CWinMaintenanceControler::getInstance(this);
    CWinSchedulerControler::getInstance(this);
    CWinStreamControler::getInstance(this);  

    //Construction de toutes les boites de dialog
    CDialogStopCycle::getInstance();
    CDialogCopyFiles::getInstance();
    CDialogInfo::getInstance();
    CDialogMessage::getInstance();
    CDialogPassword::getInstance();
    CDialogPaveNum::getInstance();
    CDialogRestauration::getInstance();
    CDialogResultatEtalon::getInstance();
    CDialogValEtalon::getInstance();
    
	CUserSession::getInstance()->objectRegister(this);

	
	//Controles de la fenêtre principale
	m_bEnStop = false;
	m_bEnPause = false;
	
	QPixmapCache::setCacheLimit(128);
	qDebug() << "#### FIN CWinMainControler::CWinMainControler" << endl;

	//récupération des erreurs
	QTimer* timerGetError = new QTimer(this);
	timerGetError->setInterval(1000);
	connect(timerGetError, SIGNAL(timeout()), this, SLOT(getErrorIOAndJBus()));
	timerGetError->start();
	
#ifdef SCREENSHOTS
	m_nbScreenshot = 0;
	QTimer* timerScreenShot = new QTimer(this);
	timerScreenShot->setInterval(3000);
	connect(timerScreenShot, SIGNAL(timeout()), this, SLOT(takeScreenshot()));
	timerScreenShot->start();
	//Fin screenshot
#endif

}

//SLOT
void CWinMainControler::getErrorIOAndJBus()
{
	m_pSupervision->getAnalyseur()->SetRemoteControl();
	if (   m_pSupervision->getAnalyseur()->m_ExternalInterface.m_pCarteIO->bGetError() 
		|| m_pSupervision->getAnalyseur()->m_ExternalInterface.m_pCarteJbusSlave->bGetError())
	{
		TRACE_DEBUG_IHM(eError,eCycle,eErrorAppRunThread);
		m_pSupervision->getAnalyseur()->m_bStatusFailure.bSetVal(1);
	}

}

//SLOT pour screenshot
void CWinMainControler::takeScreenshot()
{
	qDebug() << "SCREENSHOT TAKEN" << endl;

	
	QPixmap pixmap = QPixmap::grabWindow(QApplication::desktop()->winId());

	QString format = "png";
	QString fileName = QDir::currentPath() + tr("/screenshot")+ QString::number(++m_nbScreenshot)+"." + format;
	//QString fileName = "/Hard Disk2/screenshot" + QString::number(++m_nbScreenshot)+"." + format;

    if (!fileName.isEmpty())
        pixmap.save(fileName, format.toAscii(), 100);
}
//SLOT
void CWinMainControler::btPlayPausePressed()
{
	if(CUserSession::getInstance()->loginUser())
	{
		if(m_pModel->getStop())//m_bEnStop)
		{
			m_pModel->setRun();
			m_bEnStop = false;
		}
		else if(!m_pModel->getPause())//!m_bEnPause)
		{
			m_pModel->setPause();
			m_bEnPause = true;
		}
		else
		{
			m_pModel->setUnpause();
			m_bEnPause = false;
		}
	}
}
//SLOT
void CWinMainControler::btStopPressed()
{
	if(!m_pModel->getStop())//!m_bEnStop)
	{
	//Accept = 1   reject =0
	CDialogMessage* dialogMsg = CDialogMessage::getInstance();
	dialogMsg->setLblMsg(tr("Voulez-vous vraiment \narrêter le cycle ?"));
		if(CUserSession::getInstance()->loginUser() && dialogMsg->exec())
		{
			
			m_pModel->setStop();
			m_bEnStop = true;
		}
	}
	
}
//SLOT
void CWinMainControler::btStopEndCylePressed()
{
	//Accept = 1   reject =0
	if(!m_pModel->getStop())//!m_bEnStop)
	{
		CDialogMessage* dialogMsg = CDialogMessage::getInstance();
		dialogMsg->setLblMsg(tr("Voulez-vous vraiment \narrêter en fin de cycle ?"));
		if(CUserSession::getInstance()->loginUser() && dialogMsg->exec())
		{
			
			m_pModel->setStopEndCycle();
			m_bEnStop = true;
		}
	}
}
//SLOT	
void CWinMainControler::btNextPressed()
{
	CDialogMessage* dialogMsg = CDialogMessage::getInstance();
	dialogMsg->setLblMsg(tr("Voulez-vous vraiment \naller au cycle suivant?"));
	if(CUserSession::getInstance()->loginUser() && dialogMsg->exec())
	{
		m_pModel->setNext();
	}	
}
//SLOT
void CWinMainControler::btDiagPressed()
{

}
//SLOT
void CWinMainControler::btAlarmPressed()
{
	if(m_pDialogAlarm->updateAlarms())
	{
		m_pDialogAlarm->showFullScreen();
	}
	else
	{
		CDialogMessage::getInstance()->setLblMsg(tr("Pas d'alarme."), false);
		CDialogMessage::getInstance()->exec();
	}
		
}
//SLOT 
void CWinMainControler::btDetailPressed(int numStream)
{
	qDebug() <<"CWinMainControler::btDetailPressed1(int numStream) " << numStream;
	CWinStreamControler::getInstance(this)->execControler(numStream);
}


//SLOT
void CWinMainControler::btMeasureCardPressed()
{
    if(CUserSession::getInstance()->loginUser() )
    {
        if(m_pModel->getStop() || CDialogStopCycle::getInstance()->exec()) 
        {
            if(!m_pModel->getStop())
            {
                m_pModel->setStop();
            }

            m_pModel->setModeMaintenance(true);
            CWinElecTestControler::getInstance(this)->execControler();
        }

    }
	
}
//SLOT
void CWinMainControler::btExternalCardPressed()
{
    if(CUserSession::getInstance()->loginUser() )
    {
        if(m_pModel->getStop() || CDialogStopCycle::getInstance()->exec()) 
        {
            if(!m_pModel->getStop())
            {
                m_pModel->setStop();
            }

            m_pModel->setModeMaintenance(true);
            CWinExternalCardControler::getInstance(this)->execControler();
        }

    }
}
//SLOT
void CWinMainControler::btEVPompePressed()
{
    if(CUserSession::getInstance()->loginUser() )
    {
        if(m_pModel->getStop() || CDialogStopCycle::getInstance()->exec()) 
        {
            if(!m_pModel->getStop())
            {
                m_pModel->setStop();
            }

            m_pModel->setModeMaintenance(true);
            CWinEVPompeControler::getInstance(this)->execControler();
        }

    }
}
//SLOT
void CWinMainControler::btMaintenancePressed()
{
    //Accept = 1   reject =0
    if(CUserSession::getInstance()->loginUser() )
    {
        if(m_pModel->getStop() || CDialogStopCycle::getInstance()->exec()) 
        {
            if(!m_pModel->getStop())
            {
                m_pModel->setStop();
            }

            m_pModel->setModeMaintenance(true);
            CWinMaintenanceControler::getInstance(this)->execControler();
        }

    }
}
//SLOT
void CWinMainControler::btSequenceurPressed()
{
	//Accept = 1   reject =0
	if(CUserSession::getInstance()->loginUser())// && CDialogStopCycle::getInstance(m_pModel)->cycleStoped())
	{
		CWinSchedulerControler::getInstance(this)->execControler();
	}
	
}
//SLOT
void CWinMainControler::btCopyLogFilesPressed()
{
	//Accept = 1   reject =0
	if(CUserSession::getInstance()->loginUser())// && CDialogStopCycle::getInstance(m_pModel)->cycleStoped())
	{
		CDialogCopyFiles::getInstance()->exec();
	}
}
//SLOT
void CWinMainControler::btExplorerPressed()
{
	//Accept = 1   reject =0
	if(CUserSession::getInstance()->loginAdmin())
	{
		QProcess::execute("\\windows\\explorer.exe");
	}
}
//SLOT
void CWinMainControler::btInformationPressed()
{
	CDialogInfo::getInstance()->exec();
}
//SLOT
void CWinMainControler::btSavePressed()
{
	//Accept = 1   reject =0
	if(CUserSession::getInstance()->loginUser())
	{
		if(CDialogRestauration::getInstance()->exec())
		{
			//restauration ok, pop up ?
		}
	
	}
}
//SLOT
void CWinMainControler::btParameterPressed()
{

	////Accept = 1   reject =0
	//if(CUserSession::getInstance()->loginAdmin() && CDialogStopCycle::getInstance(m_pModel)->cycleStoped())
	//{
	//	m_pView->close();
	//}
}
//Repaint le graph que si le graph affiche la bonne page 
void CWinMainControler::askRepaintGraph(int arg_numStream)
{
    if(arg_numStream == m_CurrentGraphPage)
        m_pView->repaintGraph(arg_numStream);
}
CWinMainModel* CWinMainControler::getMainModel()
{
    return m_pModel;
}

//SLOT
void CWinMainControler::btNextGraphPressed()
{
    if(m_CurrentGraphPage<m_pModel->getNbStream()-1)
    {
        ++m_CurrentGraphPage;
        m_pView->repaintGraph(m_CurrentGraphPage);
        m_pView->setEnabledBtPrevGraph(true);
        if(m_CurrentGraphPage>=m_pModel->getNbStream()-1)
            m_pView->setEnabledBtNextGraph(false);
    }
    
}
//SLOT
void CWinMainControler::btPrevGraphPressed()
{
    if(m_CurrentGraphPage>0)
    {
        --m_CurrentGraphPage;
        m_pView->repaintGraph(m_CurrentGraphPage);
        m_pView->setEnabledBtNextGraph(true);
        if(m_CurrentGraphPage <= 0)
            m_pView->setEnabledBtPrevGraph(false);
    }
}
//SLOT
void CWinMainControler::btQuitPressed()
{
	//Accept = 1   reject =0
	CDialogMessage* dialogMsg = CDialogMessage::getInstance();
	dialogMsg->setLblMsg(tr("Voulez-vous vraiment \narrêter l'application ?"));
	if(CUserSession::getInstance()->loginAdmin() && dialogMsg->exec())
	{
		m_pView->close();
	}
}
//SLOT
void CWinMainControler::tabChanged(int index)
{
	qDebug() << "###### tab num " << index << endl;
	switch(index)
	{
		
		//Tab mesure et tab graph
		case 0:
		case 3:
			m_pModel->setStartTimerCycle();
			m_pModel->setStopTimerDiag();
            m_pView->repaintGraph(m_CurrentGraphPage);
			break;
		//tab diag
		case 1:
			m_pModel->setStopTimerCycle();
			m_pModel->setStartTimerDiag();

			break;
		//autre
		default:
			m_pModel->setStopTimerCycle();
			m_pModel->setStopTimerDiag();	
			break;
	}
}
void CWinMainControler::execControler()
{
	m_pModel->setModeMaintenance(false);	
	m_pView->showFullScreen();
}

//SLOT
void CWinMainControler::userSessionClosed()
{
	qDebug() << "SESSION CLOSED" ;
}
