#include "CWinExternalCardModel.h"
#include "CSupervision.h"
#include "CWinElecTestView.h"
#include "CStreamModel.h"
#include "CCmdJBusRunnable.h"


#include "header_qt.h"


#define SD_ON "SD_ON_"
#define SD_OFF "SD_OFF_"
#define SORTIE_ANA "SORTIE_ANA_"
#define ENTREES_D "ENTREES_D"



CWinExternalCardModel::CWinExternalCardModel(CSupervision* argpSupervision, CWinElecTestView* argpView)//, CWinExternalCardView* argpView)
{
	//qDebug() << "### Instance CWinExternalCardModel" << endl;
	m_pSupervision = argpSupervision;
    m_threadPool = new QThreadPool(this);
    m_mutex = new QMutex();
	m_pView = argpView;

	//m_pSupervision->getAnalyseur();
	//m_pSupervision->getCarteIO();
	/*m_pAnalyseur = argpAnalyseur;
	m_pCarteIO = argpCarteIO;*/
	setRequetesJBus();


    m_timerCmdEntree = new QTimer(this);
    m_timerCmdEntree->setInterval(1000);
    connect(m_timerCmdEntree, SIGNAL(timeout()), this, SLOT(cmdGetEntrees()));

#ifdef _X86_
	{
	QTimer *timerWatchDog = new QTimer(this);
	connect(timerWatchDog, SIGNAL(timeout()), this, SLOT(trigerWatchdog()));
	timerWatchDog->start(300000);
	}
#endif

#ifdef SULFITE
	{
	QTimer *timerTrigerDigitOut8 = new QTimer(this);
	connect(timerTrigerDigitOut8, SIGNAL(timeout()), this, SLOT(slotTrigerDigitOut8()));
	//timerTrigerDigitOut8->start(300000);
	timerTrigerDigitOut8->start(1200000);
	}
#endif
}

void CWinExternalCardModel::setRequetesJBus()
{
	
	TCHAR szText[260];
	bCopyFile(szGetFullPathName(_T("InterfaceIO.ini"),szText),SZ_FIC_TEMP,FALSE);
	    

    dwGetPrivateProfileString(_T("Config_io"), _T("BoardNumber"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
	QString sTmp = QString::fromUtf16 ((const ushort *)szText);
	int nbCarteIO = sTmp.toInt();
	
    qDebug() << "Nombre de carte IO : " <<  QString::number(nbCarteIO);

    m_nNumSDVirtuel = 0;
    m_nNumSAVirtuel = 0;
    m_nNumEDVirtuel = 0;


    for(int numCarte=0; numCarte<nbCarteIO; ++numCarte)
    {
        QString sSectionIni = "Board_" + QString::number(numCarte);
      
	    dwGetPrivateProfileString((LPCTSTR)sSectionIni.utf16(), _T("Config_Digi_Out"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
	    QString sConfigDigiOut = QString::fromUtf16 ((const ushort *)szText);
	    QStringList sListConfigDigiOut = sConfigDigiOut.split("|");

        dwGetPrivateProfileString((LPCTSTR)sSectionIni.utf16(), _T("Config_Digi_OutSecurite"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
	    QString sConfigDigiOutSecurite = QString::fromUtf16 ((const ushort *)szText);
	    QStringList sListConfigDigiOutSecurite = sConfigDigiOutSecurite.split("|");

		QString sConfigTemp = "";
	    int nNumSDPhysique = 0;
	    int nNumSAPhysique = 0;
	    int nNumEDPhysique = 0;

	    TCHAR szRQ[500];
	    TCHAR szRP[500];


	    foreach(sConfigTemp, sListConfigDigiOut)
	    {
            sSectionIni = "Board_" + QString::number(numCarte);
		    if(sConfigTemp == "1" || sConfigTemp == "2")
		    {
    			m_listDigiOutSecurite.append(sListConfigDigiOutSecurite.at(nNumSDPhysique).toInt());

    	        QString sRqtON;
    	        QString sRqtOFF;
                QString sLbl;
			   
			    m_pSupervision->addKeyOnMapRQTComJBUSIO(SD_ON + QString::number(m_nNumSDVirtuel));
			    m_pSupervision->addKeyOnMapRQTComJBUSIO(SD_OFF + QString::number(m_nNumSDVirtuel));
                sLbl = QString("Digi_Out_Label_") + QString::number(nNumSDPhysique);
			    dwGetPrivateProfileString((LPCTSTR)sSectionIni.utf16(), (LPCTSTR)sLbl.utf16(),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
                m_vDigiOutLabels.append(  QString("(") + QString::number(numCarte+1) + QString(")")
                                        + QString::fromUtf16 ((const ushort *)szText));
			    //SDx ON
                sRqtON = QString::number(numCarte+1) + QString("|5|0x7") + QString::number(nNumSDPhysique) + QString("|1|0");
			    /*_stprintf(szRQ,_T("1|5|0x70|1|0")); sd1
			    _stprintf(szRP,_T("1|5|0x70|1|0"));*/
                _stprintf(szRQ, (LPCTSTR)sRqtON.utf16());
			    _stprintf(szRP, (LPCTSTR)sRqtON.utf16());
			    m_pSupervision->getCarteIO()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
			    //SDx OFF
                sRqtOFF = QString::number(numCarte+1) + QString("|5|0x7") + QString::number(nNumSDPhysique) + QString("|0|0");
			    _stprintf(szRQ,(LPCTSTR)sRqtOFF.utf16());
			    _stprintf(szRP,(LPCTSTR)sRqtOFF.utf16());
			    m_pSupervision->getCarteIO()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
				
			    ++m_nNumSDVirtuel;
		    }
		    ++nNumSDPhysique;

        }

        //Requete pour valeur ana
        dwGetPrivateProfileString((LPCTSTR)sSectionIni.utf16(), _T("Config_Analog_Out"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
        //dwGetPrivateProfileString(_T("Board_0"), _T("Config_Digi_Out"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
        QString sConfigAnalogOut = QString::fromUtf16 ((const ushort *)szText);
        QStringList sListConfigAnalogOut = sConfigAnalogOut.split("|");
            
        foreach(sConfigTemp, sListConfigAnalogOut)
        {
            if(sConfigTemp == "1" || sConfigTemp == "2")
		    {
                QString sRqt;
                QString sRep;
	            QString sLbl;

               
                m_pSupervision->addKeyOnMapRQTComJBUSIO(SORTIE_ANA+ QString::number(m_nNumSAVirtuel));
                sLbl = QString("Analog_Out_Label_") + QString::number(nNumSAPhysique);
				qDebug() << "###### Analog_Out " << sLbl;
		        dwGetPrivateProfileString((LPCTSTR)sSectionIni.utf16(), (LPCTSTR)sLbl.utf16(),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
		        m_vAnalogOutLabels.append(QString::fromUtf16 ((const ushort *)szText));
                m_listNumCarteSA.append(numCarte); //retiens la carte pour chaque entrées
                m_listNumMesureSA.append(nNumSAPhysique);
                //nNumSAPhysique => num de la sorite en physique et numéro de la mesure (à changer si on utilise plus de 2 mesures)
                sRqt = QString::number(numCarte+1) +  //num carte physique JBUS
                       QString("|16|0x003") + QString::number(nNumSAPhysique*2) + //num de sortie (0ou 1)
                       QString("|01|02|0x0")+ QString::number(numCarte) + //num voie
                       QString("0") + QString::number(nNumSAPhysique) + //num mesure (0 ou 1)
                       QString("0414"); 
                sRep = QString::number(numCarte+1) + QString("|16|0x003") + QString::number(nNumSAPhysique*2) + QString("|01");
                qDebug() << "m_nNumSAVirtuel " << m_nNumSAVirtuel;
                qDebug() << sRqt;
                qDebug() << sRep;
                /* _stprintf(szRQ,_T("1|16|0x0030|02|04|0x00000414|0"));
                _stprintf(szRP,_T("1|16|0x0030|02"));*/
                _stprintf(szRQ,(LPCTSTR)sRqt.utf16());
                _stprintf(szRP,(LPCTSTR)sRep.utf16());
                m_pSupervision->getCarteIO()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
                
                ++m_nNumSAVirtuel;
            }
	        ++nNumSAPhysique;
        }
        
        //Requete pour lecture ED lecture direct de 2 valeurs
        dwGetPrivateProfileString((LPCTSTR)sSectionIni.utf16(), _T("Config_Digi_In"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
        //dwGetPrivateProfileString(_T("Board_0"), _T("Config_Digi_Out"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
        QString sConfigDigiIn = QString::fromUtf16 ((const ushort *)szText);
        QStringList sListConfigDigiIn = sConfigDigiIn.split("|");
        
        dwGetPrivateProfileString((LPCTSTR)sSectionIni.utf16(), _T("Config_Digi_InSecurite"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
	    QString sConfigDigiInSecurite = QString::fromUtf16 ((const ushort *)szText);
	    QStringList sListConfigDigiInSecurite = sConfigDigiInSecurite.split("|");

        qDebug() << "sListConfigDigiIn " << sListConfigDigiIn;
        foreach(sConfigTemp, sListConfigDigiIn)
        {
            if(sConfigTemp == "1" || sConfigTemp == "2")
		    {
                m_listDigiInSecurite.append(sListConfigDigiInSecurite.at(nNumEDPhysique).toInt());
                QString sRqt;
                QString sRep;
	            QString sLbl;

                m_pSupervision->addKeyOnMapRQTComJBUSIO(ENTREES_D+ QString::number(m_nNumEDVirtuel));
                sLbl = QString("Digi_In_Label_") + QString::number(nNumEDPhysique);
		        dwGetPrivateProfileString((LPCTSTR)sSectionIni.utf16(), (LPCTSTR)sLbl.utf16(),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
		        m_vDigiInLabels.append(QString::fromUtf16 ((const ushort *)szText));
                m_listNumCarteED.append(numCarte); //retiens la carte pour chaque entrées
                m_listNumEntreePhysiqueED.append(nNumEDPhysique);
                if( (nNumEDPhysique%2) == 0) //paire 1 entrée 
                {
                    sRqt = QString::number(numCarte+1) +  //num carte physique JBUS
                        QString("|01|0x006") + QString::number(nNumEDPhysique) + //num de sortie (1ou 2)
                        QString("|01");
                    sRep = QString::number(numCarte+1) +  //num carte physique JBUS
                        QString("|01|01|0x0") + QString::number(numCarte) +//num de voie (m_Active)
                        QString("ff0334");
                }
                else //2eme entrée
                {
                    sRqt = QString::number(numCarte+1) +  //num carte physique JBUS
                        QString("|01|0x006") + QString::number(nNumEDPhysique) + //num de sortie (1ou 2)
                        QString("|01");
                    sRep = QString::number(numCarte+1) +  //num carte physique JBUS
                        QString("|01|01|0x0") + QString::number(numCarte) +//num de voie (m_IsRunning)
                        QString("ff0337");
                }
                _stprintf(szRQ,(LPCTSTR)sRqt.utf16());
                _stprintf(szRP,(LPCTSTR)sRep.utf16());
                m_pSupervision->getCarteIO()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());

                ++m_nNumEDVirtuel;
            }
            ++nNumEDPhysique;
        }
        //Lecture des deux sorties par carte d'un coup
        
        
        
      
       
       /* _stprintf(szRQ,_T("1|01|0x0060|02"));
          _stprintf(szRP,_T("1|01|01|0x00ff0334|0xffff039f"));*/
        
		
    }
    

}

//Méthode appelé par les thread de m_threadPool
void CWinExternalCardModel::sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface)
{
    QMutexLocker locker(m_mutex);
    //qDebug() << "WinExternalCardModel::sendCmdJBus : " << arg_numRQT;
    m_cycleStep.bExecuteNumExchange(arg_numRQT, arg_elemList, TRUE, TRUE, arg_interface);
}
//SLOT
void CWinExternalCardModel::trigerWatchdog()
{
	//qDebug() << "####  CWinExternalCardModel::trigerWatchdog() " ;
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSIO(SD_ON + QString::number(0))
                                            , m_pSupervision->getCarteIO()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
    Sleep(500);
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSIO(SD_OFF + QString::number(0))
                                            , m_pSupervision->getCarteIO()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
}
//SLOT 
void CWinExternalCardModel::slotTrigerDigitOut8(){
	if(    (  !m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal() 
		   || !m_pSupervision->getAnalyseur()->pGetAt(0)->m_Active.ucGetVal()
		   || m_pSupervision->getAnalyseur()->m_NumCurrentStream.ucGetVal() == 99 )
		&& m_pSupervision->getAnalyseur()->m_CmdRemoteControl.ucGetVal() != CSupervision::eREMOTE_SAV){

		m_threadPool->start(new CCmdJBusRunnable( this
												, m_pSupervision->getNumRQTComJBUSIO(SD_ON + QString::number(7))
												, m_pSupervision->getCarteIO()->getListExchange()
												, m_pSupervision->getAnalyseur()->m_ExternalInterface));
		Sleep(2000);
		m_threadPool->start(new CCmdJBusRunnable( this
												, m_pSupervision->getNumRQTComJBUSIO(SD_OFF + QString::number(7))
												, m_pSupervision->getCarteIO()->getListExchange()
												, m_pSupervision->getAnalyseur()->m_ExternalInterface));
	}
}
//SLOT
void CWinExternalCardModel::cmdGetEntrees()
{
    for(int i=0; i<this->m_vDigiInLabels.count(); ++i)
        m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSIO(ENTREES_D+QString::number(i))
                                            , m_pSupervision->getCarteIO()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
    m_pView->dataUpdated();
}
bool CWinExternalCardModel::getEtatEntree(int arg_numEntree)const
{
    if(m_listNumEntreePhysiqueED.at(arg_numEntree)%2 == 0)
        return m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteED.at(arg_numEntree))->m_Active.ucGetVal();
    else
        return m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteED.at(arg_numEntree))->m_IsRunning.ucGetVal();
    return false;
}
bool CWinExternalCardModel::getEtatEntreePhysique(int arg_numEntree)const
{
    bool bRetour;
    if(m_listNumEntreePhysiqueED.at(arg_numEntree)%2 == 0)
        bRetour =   (bool)m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteED.at(arg_numEntree))->m_Active.ucGetVal()
                  ^ m_listDigiInSecurite.at(arg_numEntree);
    else
        bRetour =   (bool)m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteED.at(arg_numEntree))->m_IsRunning.ucGetVal()
                  ^ m_listDigiInSecurite.at(arg_numEntree);
    
    return bRetour;
}
void CWinExternalCardModel::cmdRelais(const int& nNumRelais,const bool& bRelaisActif)
{
	int numRQT = 0;
	if(bRelaisActif)
        numRQT = m_pSupervision->getNumRQTComJBUSIO(SD_ON + QString::number(nNumRelais));    
	else
        numRQT = m_pSupervision->getNumRQTComJBUSIO(SD_OFF + QString::number(nNumRelais));

	m_threadPool->start(new CCmdJBusRunnable( this
                                            , numRQT
                                            , m_pSupervision->getCarteIO()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
}

void CWinExternalCardModel::cmdSortieAnalogique(const int& arg_nNumSortie, const int& arg_nValeurAna)
{

    qDebug() << "cmdSortieAnalogique" << arg_nNumSortie << " " << m_listNumCarteSA.at(arg_nNumSortie) << " " << m_listNumMesureSA.at(arg_nNumSortie);
	int tmp;
	if(arg_nValeurAna == 4)
	{
		tmp = m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_nNumSortie))
                                            ->pGetAt(m_listNumMesureSA.at(arg_nNumSortie))->m_ValMinConvertisseur.nGetVal();
	}
	else if(arg_nValeurAna == 12)
	{
		tmp =  m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_nNumSortie))
                                            ->pGetAt(m_listNumMesureSA.at(arg_nNumSortie))->m_ValMinConvertisseur.nGetVal()
			+ ((  m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_nNumSortie))
                                            ->pGetAt(m_listNumMesureSA.at(arg_nNumSortie))->m_ValMaxConvertisseur.nGetVal()
				 -m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_nNumSortie))
                                            ->pGetAt(m_listNumMesureSA.at(arg_nNumSortie))->m_ValMinConvertisseur.nGetVal())
				/2);
	}
	else //20mA 
	{
		tmp = m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_nNumSortie))
                                            ->pGetAt(m_listNumMesureSA.at(arg_nNumSortie))->m_ValMaxConvertisseur.nGetVal();
	}
    qDebug() << "tmp " << tmp;
	m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_nNumSortie))
                                            ->pGetAt(m_listNumMesureSA.at(arg_nNumSortie))->m_ValAna.bSetVal(tmp);

    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSIO(SORTIE_ANA+QString::number(arg_nNumSortie))
                                            , m_pSupervision->getCarteIO()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	
}

QString CWinExternalCardModel::getLblValAna()const
{
	return QString::fromUtf16((const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValAna.szGetLabel()
											, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValAna.lGetLabelLength());
}
QString CWinExternalCardModel::getLblMesure()const
{
	return QString::fromUtf16((const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Val.szGetLabel()
											, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Val.lGetLabelLength());
}
QString CWinExternalCardModel::getLblValMaxConvertisseur()const
{
	return QString::fromUtf16((const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValMaxConvertisseur.szGetLabel()
											, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValMaxConvertisseur.lGetLabelLength());
}
QString CWinExternalCardModel::getLblValMinConvertisseur()const
{
	return QString::fromUtf16((const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValMinConvertisseur.szGetLabel()
											, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValMinConvertisseur.lGetLabelLength());
}
QString CWinExternalCardModel::getUniteValAna()const
{
	return QString::fromUtf16((const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValAna.m_szUnit.szGetLabel()
											, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValAna.m_szUnit.lGetLabelLength());
}
QString CWinExternalCardModel::getUniteMesure()const
{
	return QString::fromUtf16((const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Val.m_szUnit.szGetLabel()
											, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Val.m_szUnit.lGetLabelLength());
}
QString CWinExternalCardModel::getUniteValMaxConvertisseur()const
{
	return QString::fromUtf16((const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValMaxConvertisseur.m_szUnit.szGetLabel()
											, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValMaxConvertisseur.m_szUnit.lGetLabelLength());
}
QString CWinExternalCardModel::getUniteValMinConvertisseur()const
{
	return QString::fromUtf16((const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValMinConvertisseur.m_szUnit.szGetLabel()
											, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValMinConvertisseur.m_szUnit.lGetLabelLength());
}

QString CWinExternalCardModel::getValueValAna()const
{
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ValAna.nGetVal());
}
QString CWinExternalCardModel::getValueMesure()const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)(m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Val.szGetConfig(szText, 250)));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Val.fGetVal(), 'f', sPrecision.toInt());
}
QString CWinExternalCardModel::getValueValMaxConvertisseur(int arg_numSortie)const
{
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_numSortie))
                                                         ->pGetAt(m_listNumMesureSA.at(arg_numSortie))->m_ValMaxConvertisseur.nGetVal());
}
QString CWinExternalCardModel::getValueValMinConvertisseur(int arg_numSortie)const
{
	
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_numSortie))
                                                         ->pGetAt(m_listNumMesureSA.at(arg_numSortie))->m_ValMinConvertisseur.nGetVal());
}

void CWinExternalCardModel::setValMaxConvertisseur(int arg_numSortie, const QString& arg_sVal)
{
	m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_numSortie))
                                  ->pGetAt(m_listNumMesureSA.at(arg_numSortie))->m_ValMaxConvertisseur.bSetVal(arg_sVal.toInt());
    QString sSection = QString("CStream") + QString::number(m_listNumCarteSA.at(arg_numSortie))
                     + QString("_CMesure") + QString::number(m_listNumMesureSA.at(arg_numSortie));
    CMesureModel::writeElemConfigIni((WCHAR *)sSection.utf16(), 
                                    _T("m_ValMaxConvertisseur"), 
                                    &m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_numSortie))
                                                                   ->pGetAt(m_listNumMesureSA.at(arg_numSortie))
                                                                   ->m_ValMaxConvertisseur);	
}

void CWinExternalCardModel::setValMinConvertisseur(int arg_numSortie, const QString& arg_sVal)
{
    m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_numSortie))
                                  ->pGetAt(m_listNumMesureSA.at(arg_numSortie))->m_ValMinConvertisseur.bSetVal(arg_sVal.toInt());
    QString sSection = QString("CStream") + QString::number(m_listNumCarteSA.at(arg_numSortie))
                     + QString("_CMesure") + QString::number(m_listNumMesureSA.at(arg_numSortie));
    CMesureModel::writeElemConfigIni((WCHAR *)sSection.utf16(), 
                                    _T("m_ValMinConvertisseur"), 
                                    &m_pSupervision->getAnalyseur()->pGetAt(m_listNumCarteSA.at(arg_numSortie))
                                                                   ->pGetAt(m_listNumMesureSA.at(arg_numSortie))
                                                                   ->m_ValMinConvertisseur);
	
}