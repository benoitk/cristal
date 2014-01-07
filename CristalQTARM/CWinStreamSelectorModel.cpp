#include "CWinStreamSelectorModel.h"
#include "CSupervision.h"
#include "CWinElecTestView.h"
#include "CStreamModel.h"
#include "CCmdJBusRunnable.h"

#include "header_qt.h"


// En fonction de l'ordre d'ajout des requetes : A rendre dynamique, sinon ce sera inmaintenable (voir aussi WinMeasureCardModel)
#define STREAM "STREAM_"


CWinStreamSelectorModel::CWinStreamSelectorModel(CSupervision* argpSupervision)//, CWinEVPompeView* argpView)
{
	qDebug() << "### Instance CWinStreamSelectorModel" << endl;
	m_pSupervision = argpSupervision;
	//m_pView = argpView;

    m_threadPool = new QThreadPool(this);
    m_mutex = new QMutex();

	
    for(int i=0; i< m_pSupervision->getAnalyseur()->iGetNbrStream(); ++i)
    {
        int nbPasAFaire = 0;
        switch(i)
        {
            case 0 : nbPasAFaire = 18;
            break;
            case 1 : nbPasAFaire = 43;
            break;
            case 2 : nbPasAFaire = 68;
            break;
            case 3 : nbPasAFaire = 118;
            break;
            case 4 : nbPasAFaire = 143;
            break;
            case 5 : nbPasAFaire = 168;
            break;
            default : nbPasAFaire = 18;
            break;
        }
        TCHAR szRQ[5000];
	    TCHAR szRP[5000];
        QString sReq = QString("10|16|0x0300|5|10|994|255|") +
                       QString::number(nbPasAFaire)+
                       QString("|10|70");
        m_pSupervision->addKeyOnMapRQTComJBUSMesure(STREAM + QString::number(i));
	    _stprintf(szRQ,(LPCTSTR)sReq.utf16());
	    _stprintf(szRP,_T("10|16|0x0300|5"));
	    m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
	    
    }
	
    /*_stprintf(szRQ,_T("10|16|0x0300|5|10|994|255|0|10|70"));
    _stprintf(szRP,_T("10|16|0x0300|5"));*/
	
	
					
	

}
//Méthode appelé par les thread de m_threadPool
void CWinStreamSelectorModel::sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface)
{
    QMutexLocker locker(m_mutex);
   // qDebug() << "CWinEVPompeModel::sendCmdJBus : " << arg_numRQT;
    m_cycleStep.bExecuteNumExchange(arg_numRQT, arg_elemList, TRUE, TRUE, arg_interface);
}

void CWinStreamSelectorModel::cmdSelectionVoie(int arg_nNumVoie)
{
    int numRQT = m_pSupervision->getNumRQTComJBUSMesure(STREAM + QString::number(arg_nNumVoie));
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , numRQT
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));

}

int CWinStreamSelectorModel::getNbStream() const
{
    return m_pSupervision->getAnalyseur()->iGetNbrStream();
}