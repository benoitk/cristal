#include "CWinMeasureCardModel.h"
#include "CSupervision.h"
#include "CWinMeasureCardView.h"
#include "CStreamModel.h"
#include "CCmdJBusRunnable.h"

#include "header_qt.h"


// En fonction de l'ordre d'ajout des requetes : A rendre dynamique, sinon ce sera inmaintenable (voir aussi WinEVPompeModel)
#define STIRRER_ON	"STIRRER_ON"
#define STIRRER_OFF	"STIRRER_OFF"
#define DOOR_ON		"DOOR_ON"
#define DOOR_OFF	"DOOR_OFF"
#define VALVE_ON	"VALVE_ON"
#define VALVE_OFF	"VALVE_OFF"
#define HEATER_ON	"HEATER_ON"
#define HEATER_OFF	"HEATER_OFF"

#define ORGANNE_LOCAL_ON "ORGANNE_LOCAL_ON"
#define ORGANNE_LOCAL_OFF "ORGANNE_LOCAL_OFF"

CWinMeasureCardModel::CWinMeasureCardModel(CSupervision* argpSupervision)//, CWinMeasureCardView* argpView)
{
	
	m_pSupervision = argpSupervision;
	//m_pView = argpView;

    m_threadPool = new QThreadPool(this);
    m_mutex = new QMutex();
	
	TCHAR szRQ[500];
	TCHAR szRP[500];
	TCHAR szText[260];

	bCopyFile(szGetFullPathName(_T("InterfaceMesure.ini"),szText),SZ_FIC_TEMP,FALSE);

	dwGetPrivateProfileString(_T("Config_local"), _T("Config_Local"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
	QString sConfigLocal = QString::fromUtf16 ((const ushort *)szText);
	QStringList sListConfigLocal = sConfigLocal.split("|");
	QString sConfigTemp = "";
	int nNumLocalPhysique = 0;
	int nNumLocalVirtuel = 0;
	
	foreach(sConfigTemp, sListConfigLocal)
	{
		++nNumLocalPhysique;
		if(sConfigTemp == "1")
		{
			m_pSupervision->addKeyOnMapRQTComJBUSMesure(ORGANNE_LOCAL_ON + QString::number(nNumLocalVirtuel));
			m_pSupervision->addKeyOnMapRQTComJBUSMesure(ORGANNE_LOCAL_OFF + QString::number(nNumLocalVirtuel++));
			qDebug() << "### Instance CWinMeasureCardModel | nNumLocalPhysique:"<< nNumLocalPhysique << endl;
			switch(nNumLocalPhysique)
			{	
				case 1:
					dwGetPrivateProfileString(_T("Config_local"), _T("Local_Label_0"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
					m_vLocalLabels.append(QString::fromUtf16 ((const ushort *)szText).split("|").first());
					m_vLocalSecuriteOn.append(false);
					//LOCAL1_ON
					_stprintf(szRQ,_T("10|5|0x1200|1|0"));
					_stprintf(szRP,_T("10|5|0x1200|1|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					//LOCAL2_OFF
					_stprintf(szRQ,_T("10|5|0x1200|0|0"));
					_stprintf(szRP,_T("10|5|0x1200|0|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					break;
				case 2:
					dwGetPrivateProfileString(_T("Config_local"), _T("Local_Label_1"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
					m_vLocalLabels.append(QString::fromUtf16 ((const ushort *)szText).split("|").first());
					m_vLocalSecuriteOn.append(false);
					//LOCAL1_ON
					_stprintf(szRQ,_T("10|5|0x1201|1|0"));
					_stprintf(szRP,_T("10|5|0x1201|1|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					//LOCAL2_OFF
					_stprintf(szRQ,_T("10|5|0x1201|0|0"));
					_stprintf(szRP,_T("10|5|0x1201|0|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					break;
				case 3:
					dwGetPrivateProfileString(_T("Config_local"), _T("Local_Label_2"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
					m_vLocalLabels.append(QString::fromUtf16 ((const ushort *)szText).split("|").first());
					m_vLocalSecuriteOn.append(false);
					//LOCAL1_ON
					_stprintf(szRQ,_T("10|5|0x1202|1|0"));
					_stprintf(szRP,_T("10|5|0x1202|1|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					//LOCAL2_OFF
					_stprintf(szRQ,_T("10|5|0x1202|0|0"));
					_stprintf(szRP,_T("10|5|0x1202|0|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					break;
				case 4:
					dwGetPrivateProfileString(_T("Config_local"), _T("Local_Label_3"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
					m_vLocalLabels.append(QString::fromUtf16 ((const ushort *)szText).split("|").first());
					m_vLocalSecuriteOn.append(false);
					//LOCAL1_ON
					_stprintf(szRQ,_T("10|5|0x1203|1|0"));
					_stprintf(szRP,_T("10|5|0x1203|1|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					//LOCAL2_OFF
					_stprintf(szRQ,_T("10|5|0x1203|0|0"));
					_stprintf(szRP,_T("10|5|0x1203|0|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					break;
				case 5:
					dwGetPrivateProfileString(_T("Config_local"), _T("Local_Label_4"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
					m_vLocalLabels.append(QString::fromUtf16 ((const ushort *)szText).split("|").first());
					m_vLocalSecuriteOn.append(true);
					//LOCAL1_ON
					_stprintf(szRQ,_T("10|5|0x1204|1|0"));
					_stprintf(szRP,_T("10|5|0x1204|1|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					//LOCAL2_OFF
					_stprintf(szRQ,_T("10|5|0x1204|0|0"));
					_stprintf(szRP,_T("10|5|0x1204|0|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					break;
				case 6:
					dwGetPrivateProfileString(_T("Config_local"), _T("Local_Label_5"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
					m_vLocalLabels.append(QString::fromUtf16 ((const ushort *)szText).split("|").first());
					m_vLocalSecuriteOn.append(false);
					//LOCAL1_ON
					_stprintf(szRQ,_T("10|5|0x1205|1|0"));
					_stprintf(szRP,_T("10|5|0x1205|1|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					//LOCAL2_OFF
					_stprintf(szRQ,_T("10|5|0x1205|0|0"));
					_stprintf(szRP,_T("10|5|0x1205|0|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					break;
				case 7:
					dwGetPrivateProfileString(_T("Config_local"), _T("Local_Label_6"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
					m_vLocalLabels.append(QString::fromUtf16 ((const ushort *)szText).split("|").first());
					m_vLocalSecuriteOn.append(false);
					//LOCAL1_ON
					_stprintf(szRQ,_T("10|5|0x1206|1|0"));
					_stprintf(szRP,_T("10|5|0x1206|1|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					//LOCAL2_OFF
					_stprintf(szRQ,_T("10|5|0x1206|0|0"));
					_stprintf(szRP,_T("10|5|0x1206|0|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					break;
				case 8:
					dwGetPrivateProfileString(_T("Config_local"), _T("Local_Label_7"),_T("0"),szText, sizeof(szText)/sizeof(TCHAR), SZ_FIC_TEMP);
					m_vLocalLabels.append(QString::fromUtf16 ((const ushort *)szText).split("|").first());
					m_vLocalSecuriteOn.append(false);
					//LOCAL1_ON
					_stprintf(szRQ,_T("10|5|0x1207|1|0"));
					_stprintf(szRP,_T("10|5|0x1207|1|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					//LOCAL2_OFF
					_stprintf(szRQ,_T("10|5|0x1207|0|0"));
					_stprintf(szRP,_T("10|5|0x1207|0|0"));
					m_pSupervision->getCarteMesure()->bAddExchangeJbus(szRQ,szRP,m_pSupervision->getAnalyseur());
					break;
			}
		}
	}

	
}

//Méthode appelé par les thread de m_threadPool
void CWinMeasureCardModel::sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface)
{
    QMutexLocker locker(m_mutex);
   // qDebug() << "CWinEVPompeModel::sendCmdJBus : " << arg_numRQT;
    m_cycleStep.bExecuteNumExchange(arg_numRQT, arg_elemList, TRUE, TRUE, arg_interface);
}

void CWinMeasureCardModel::cmdOrganne(const int& nNumOrganne, const bool& bRelaisActif)
{
	
    int numRQT = 0;
    if(bRelaisActif)
        numRQT = m_pSupervision->getNumRQTComJBUSMesure(ORGANNE_LOCAL_ON + QString::number(nNumOrganne));
    else
        numRQT = m_pSupervision->getNumRQTComJBUSMesure(ORGANNE_LOCAL_OFF + QString::number(nNumOrganne));

    m_threadPool->start(new CCmdJBusRunnable( this
                                            , numRQT
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	
}

