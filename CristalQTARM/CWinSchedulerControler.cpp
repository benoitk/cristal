#include "CWinSchedulerControler.h"
#include "CWinSchedulerView.h"
#include "CWinSchedulerModel.h"
#include "CWinMainControler.h"
#include "CUserSession.h"
#include "CDialogPaveNum.h"
#include "CDialogMessage.h"
#include "CDialogStreamChoice.h"
#include "CDialogConfigSeuil.h"

CWinSchedulerControler *CWinSchedulerControler::singletonControler = 0;

CWinSchedulerControler::CWinSchedulerControler(CWinMainControler* argpWinMainControler)
{
	m_pWinMainControler = argpWinMainControler;
	m_pSupervision = argpWinMainControler->getpSupervision();
	m_pView  = new CWinSchedulerView(this);
	m_pModel = new CWinSchedulerModel(m_pSupervision, m_pView);
	m_pView->setModel(m_pModel);
}

//SLOT fermeture de la fenêtre
void CWinSchedulerControler::btBackPressed()
{
    //Sauvegarde du séquenceur
    m_pModel->saveSequences();
	/*m_pModel->setYear(m_pView->getYear());
	m_pModel->setMonth(m_pView->getMonth());
	m_pModel->setDay(m_pView->getDay());
	m_pModel->setHour(m_pView->getHour());
	m_pModel->setMinute(m_pView->getMinute());*/
	m_pModel->setDateTime(m_pView->getYear(), m_pView->getMonth(), m_pView->getDay(), m_pView->getHour(), m_pView->getMinute());

	CUserSession::getInstance()->poke();
	CUserSession::getInstance()->objectUnregister(this);
	m_pView->close();
	//delete m_pModel;
	//delete m_pView;
	m_pWinMainControler->execControler();
	QPixmapCache::clear();
}

void CWinSchedulerControler::execControler()
{
	/*m_pView  = new CWinMeasureCardView(this);
	m_pModel = new CWinMeasureCardModel(m_pSupervision, m_pView);
	m_pView->setModel(m_pModel);*/
	//m_pView->showFullScreen();
	m_pView->loadPage();
	m_pView->showFullScreen();
	CUserSession::getInstance()->objectRegister(this);

}

CWinSchedulerControler* CWinSchedulerControler::getInstance(CWinMainControler* argpWinMainControler)
{
		if(!singletonControler)
			singletonControler = new CWinSchedulerControler(argpWinMainControler);

		return singletonControler;
}
void CWinSchedulerControler::btNumVoiePressed(int arg_numBt)
{
    Sequence seq = {
        m_pModel->getSequence(arg_numBt).iStream,
        m_pModel->getSequence(arg_numBt).iDuree
    };

   // CDialogPaveNum::getInstance()->setValueName(tr("Voie"));
    CDialogStreamChoice::getInstance()->setValue(QString::number(seq.iStream+1));
    CDialogStreamChoice::getInstance()->setNbStreamEnabled(m_pModel->getNbStream());
    
    if(CDialogStreamChoice::getInstance()->exec())
    {
        int iStream = CDialogStreamChoice::getInstance()->getValue().toInt()-1;
        if((iStream>=0 && iStream < NBR_STREAM_MAX) || iStream == 99) //99 voie de pause
            seq.iStream = iStream;
        else if(iStream > NBR_STREAM_MAX)
            seq.iStream = 99;
        else
            seq.iStream = 0;

        if(seq.iDuree == 0)//Si pas de durée, demander tout de suite sinon ne rien faire
        {
            if(seq.iStream > NBR_STREAM_MAX)
                CDialogPaveNum::getInstance()->setValueName(tr("Durée en minute"));
            else
                CDialogPaveNum::getInstance()->setValueName(tr("Durée en nombre de cycle"));
            CDialogPaveNum::getInstance()->setValue(QString::number(seq.iDuree));
            if(CDialogPaveNum::getInstance()->exec())
            {
                seq.iDuree = CDialogPaveNum::getInstance()->getValue().toInt();
                if(seq.iDuree<1) seq.iDuree = 1;
            }
            while(m_pModel->getSequence(arg_numBt-1).iDuree == 0) --arg_numBt;
        }
        m_pModel->setSequence(seq, arg_numBt);
        m_pView->loadPage();
    }

}
void CWinSchedulerControler::btTempsSeqPressed(int arg_numBt)
{
    Sequence seq = {
        m_pModel->getSequence(arg_numBt).iStream,
        m_pModel->getSequence(arg_numBt).iDuree
    };

    if(seq.iStream > NBR_STREAM_MAX)
        CDialogPaveNum::getInstance()->setValueName(tr("Durée en minute"));
    else
        CDialogPaveNum::getInstance()->setValueName(tr("Durée en cycle"));
    CDialogPaveNum::getInstance()->setValue(QString::number(seq.iDuree));
    if(CDialogPaveNum::getInstance()->exec())
    {
        seq.iDuree = CDialogPaveNum::getInstance()->getValue().toInt();
        if(seq.iDuree<1) seq.iDuree = 1;
    }
    m_pModel->setSequence(seq, arg_numBt);
    m_pView->loadPage();
}
void CWinSchedulerControler::btDeletePressed(int arg_numBt)
{
    m_pModel->deleteSequence(arg_numBt);
    m_pView->loadPage();

}
//SLOT
void CWinSchedulerControler::userSessionClosed()
{
	qDebug() << "##### CWinSchedulerControler::userSessionClosed()" << endl;
	if(!CUserSession::getInstance()->loginAsLastUser())
		btBackPressed();
}
//SLOT
void CWinSchedulerControler::btNbCyleAvantZeroPressed()
{
	if(CUserSession::getInstance()->loginUser())
	{
		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
		pPaveNum->setValue(m_pView->getNbCyleAvantZeroValue());
		pPaveNum->setValueName(m_pView->getNbCyleAvantZeroLbl());
	
		if(pPaveNum->exec())
		{
			//Ce servir des bornes configurables plus tard ! 
			int iValue = pPaveNum->getValue().toInt();
			if(iValue > 255) iValue = 255;
			if(iValue < 0) iValue = 0;
			m_pView->setNbCyleAvantZeroValue(QString::number(iValue));
		}
	}
}
//SLOT 
void CWinSchedulerControler::btRemoteCtrlPressed()
{
	if(CUserSession::getInstance()->loginUser())
	{
		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
		pPaveNum->setValue(m_pView->getRemoteCtrlValue());
		pPaveNum->setValueName(m_pView->getRemoteCtrlLbl());
	
		if(pPaveNum->exec())
		{
			//Ce servir des bornes configurables plus tard ! 
			int iValue = pPaveNum->getValue().toInt();
			if(iValue > 3) iValue = 3;
			if(iValue < 0) iValue = 0;
			m_pView->setRemoteCtrlValue(QString::number(iValue));
		}
	}
}
//SLOT 
void CWinSchedulerControler::btConsigneGainPressed()
{
	if(CUserSession::getInstance()->loginUser())
	{
		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
		pPaveNum->setValue(m_pView->getConsigneGainValue());
		pPaveNum->setValueName(m_pView->getConsigneGainLbl());
	
		if(pPaveNum->exec())
		{
			m_pView->setConsigneGainValue(QString::number(pPaveNum->getValue().toInt()));
		}
	}
}
//SLOT 
void CWinSchedulerControler::btConsigneTemperaturePressed()
{
	if(CUserSession::getInstance()->loginUser())
	{
		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
		pPaveNum->setValue(m_pView->getConsigneTemperatureValue());
		pPaveNum->setValueName(m_pView->getConsigneTemperatureLbl());
	
		if(pPaveNum->exec())
		{
			
			m_pView->setConsigneTemperatureValue(QString::number(pPaveNum->getValue().toFloat()));
		}
	}
}
//SLOT 
void CWinSchedulerControler::btReglagePressionPressed()
{
	if(CUserSession::getInstance()->loginUser())
	{
		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
		pPaveNum->setValue(m_pView->getReglagePressionValue());
		pPaveNum->setValueName(m_pView->getReglagePressionLbl());
	
		if(pPaveNum->exec())
		{			
			m_pView->setReglagePressionValue(QString::number(pPaveNum->getValue().toFloat()));
		}
	}
}
//SLOT
void CWinSchedulerControler::btTempsVoieAttentePressed()
{
    if(CUserSession::getInstance()->loginUser())
	{
		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
		pPaveNum->setValue(m_pView->getTempsVoieAttenteValue());
		pPaveNum->setValueName(m_pView->getTempsVoieAttenteLbl());
	
		if(pPaveNum->exec())
		{			
			m_pView->setTempsVoieAttenteValue(QString::number(pPaveNum->getValue().toFloat()));
		}
	}
}
//SLOT
void CWinSchedulerControler::btNumEscalveJBUSPressed()
{
    if(CUserSession::getInstance()->loginUser())
	{
		CDialogPaveNum* pPaveNum = CDialogPaveNum::getInstance();
		pPaveNum->setValue(m_pView->getNumEscalveJBUSValue());
		pPaveNum->setValueName(m_pView->getNumEscalveJBUSLbl());
	
		if(pPaveNum->exec())
		{			
            if(pPaveNum->getValue().toFloat() != m_pView->getNumEscalveJBUSValue().toFloat())
            {
			    m_pView->setNumEscalveJBUSValue(QString::number(pPaveNum->getValue().toFloat()));
                CDialogMessage::getInstance()->setLblMsg(tr("Redémarrer l'appareil."));
                CDialogMessage::getInstance()->buttonVisible(false);
                CDialogMessage::getInstance()->exec();
            }
		}
	}
}
//SLOT
void CWinSchedulerControler::btConfigSeuilPressed(int arg_numBt)
{
    int numVoie = 0;
    int numMesure = 0;
    int index = 0;
    
	
    if(CUserSession::getInstance()->loginUser())
	{
	
		
        for(int i=0; i< m_pModel->getNbStream() ; ++i)
        {
            for(int j=0; j<m_pModel->getNbMeasure(); ++j)
            {
		
                if(arg_numBt == index)
                {
                    numVoie = i;
                    numMesure = j;
                }
				++index;
            }
            ++index;
        }
	

		CDialogConfigSeuil* pPaveNum = CDialogConfigSeuil::getInstance();
       	pPaveNum->setValue(m_pModel->getConfigSeuil(numVoie, numMesure));
		if(pPaveNum->exec())
        {
			m_pView->setConfigSeuil(arg_numBt, pPaveNum->getValue());
        }
    }
}

void CWinSchedulerControler::btYearPPressed()
{
	int var = m_pView->getYear().toInt() +1;
	m_pView->setYear(QString::number(var));
}
void CWinSchedulerControler::btMonthPPressed()
{
	int var = m_pView->getMonth().toInt();
	if(var == 12) var=1;
	else ++var;

	m_pView->setMonth(QString::number(var));
}
void CWinSchedulerControler::btDayPPressed()
{
	int var = m_pView->getDay().toInt()+1;
	QDate date(m_pView->getYear().toInt(), m_pView->getMonth().toInt(), var);
	if(!date.isValid()) var = 1;

	m_pView->setDay(QString::number(var));
}
void CWinSchedulerControler::btHourPPressed()
{
	int var = m_pView->getHour().toInt();
	if(var == 24) var=1;
	else ++var;

	m_pView->setHour(QString::number(var));
}
void CWinSchedulerControler::btMinutePPressed()
{
	int var = m_pView->getMinute().toInt();
	if(var == 60) var=1;
	else ++var;

	m_pView->setMinute(QString::number(var));
}

void CWinSchedulerControler::btYearMPressed()
{
	int var = m_pView->getYear().toInt() -1;
	m_pView->setYear(QString::number(var));
}
void CWinSchedulerControler::btMonthMPressed()
{
	int var = m_pView->getMonth().toInt();
	if(var == 1) var=12;
	else --var;

	m_pView->setMonth(QString::number(var));
}
void CWinSchedulerControler::btDayMPressed()
{
	int var = m_pView->getDay().toInt()-1;
	QDate date(m_pView->getYear().toInt(), m_pView->getMonth().toInt(), var);
	if(!date.isValid())
	{
		date.setDate(m_pView->getYear().toInt(), m_pView->getMonth().toInt(), 1);
		var = date.daysInMonth();
	}

	m_pView->setDay(QString::number(var));
}
void CWinSchedulerControler::btHourMPressed()
{
	int var = m_pView->getHour().toInt();
	if(var == 1) var=24;
	else --var;

	m_pView->setHour(QString::number(var));
}
void CWinSchedulerControler::btMinuteMPressed()
{
	int var = m_pView->getMinute().toInt();
	if(var == 1) var=60;
	else --var;

	m_pView->setMinute(QString::number(var));
}