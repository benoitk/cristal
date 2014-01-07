#include "CWinMaintenanceModel.h"
#include "CWinMaintenanceView.h"
#include "CSupervision.h"
#include "CStreamModel.h"
#include "CSupervision.h"
#include "CCmdJBusRunnable.h"

//#include "header_qt.h"
CWinMaintenanceModel::CWinMaintenanceModel(CSupervision* argpSupervision, CWinMaintenanceView* argpView)
{
    m_threadPool = new QThreadPool(this);
    m_mutex = new QMutex();

	m_pSupervision = argpSupervision;;
	m_pView = argpView;
	
	setConnexion();
}


//Get Valeur variables de mesure
QString CWinMaintenanceModel::sGetMesureManuelleVal(int arg_numStream, int arg_numMeasure)const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueAfter.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueAfter.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetOffsetActuelVal(int arg_numStream)const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWater.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWater.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetOffsetCalculeVal(int arg_numStream)const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWaterNew.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWaterNew.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetEtalonRefVal(int arg_numStream, int arg_numMeasure)const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueBefore.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueBefore.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetCoefActuelVal(int arg_numStream, int arg_numMeasure)const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeff.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeff.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetCoefCalculeVal(int arg_numStream, int arg_numMeasure)const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeffNew.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeffNew.fGetVal(), 'f',sPrecision.toInt());
}

QString CWinMaintenanceModel::sGetV0Val() const//KMnO4
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_CalibZeroAir.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_CalibZeroAir.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetV2Val() const//KMnO4
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Delta.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Delta.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetEtalonEauRefVal() const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroStandard.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroStandard.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetIndicateurEauAirVal() const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_AirWaterFlag.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_AirWaterFlag.fGetVal(), 'f',sPrecision.toInt());
}
QString CWinMaintenanceModel::sGetMesurePHVal()const
{
	TCHAR szText[250];
	QString sPrecision = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_RawConcentration.szGetConfig(szText, 250));
	sPrecision = sPrecision.split("|").last().split(".").last().left(1);
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_RawConcentration.fGetVal(), 'f',sPrecision.toInt());
}
bool CWinMaintenanceModel::bGetCoefStatus(int arg_numStream, int arg_numMeasure)const
{
	//qDebug() << "CWinMaintenanceModel::bGetCoefStatus()" << m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_CalibStatusCoeff.ucGetVal();

    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibStatusCoeff.ucGetVal() > 0)
		return true;
	else
		return false;

}

bool CWinMaintenanceModel::bGetOffsetStatus(int arg_numStream)const
{
	if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibStatusZero.ucGetVal() > 0)
		return true;
	else
		return false;
}
//Get libelé de variables de mesure
QString CWinMaintenanceModel::sGetMesureManuelleLbl(int arg_numStream, int arg_numMeasure)const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueAfter.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueAfter.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetOffsetActuelLbl(int arg_numStream)const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWater.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWater.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetEtalonEauRefLbl() const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroStandard.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroStandard.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetIndicateurEauAirLbl() const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_AirWaterFlag.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_AirWaterFlag.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetMesurePHLbl()const
{
	//qDebug() << "Mesure Ph x" << m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_TurbidityStandard.fGetVal();
	//qDebug() << "Mesure Ph x - ph7" << m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_AirOpticalGain.fGetVal();


	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_RawConcentration.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_RawConcentration.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetV0Lbl() const//KMnO4
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_CalibZeroAir.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_CalibZeroAir.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetV2Lbl() const//KMnO4
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Delta.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Delta.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}

QString CWinMaintenanceModel::sGetOffsetCalculeLbl(int arg_numStream)const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWaterNew.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWaterNew.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetEtalonRefLbl(int arg_numStream, int arg_numMeasure)const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueBefore.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueBefore.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetCoefActuelLbl(int arg_numStream, int arg_numMeasure)const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeff.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeff.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetCoefCalculeLbl(int arg_numStream, int arg_numMeasure)const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeffNew.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeffNew.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetCoefSondeActuelLbl(int arg_numMeasure)const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(arg_numMeasure)->m_CalibZeroWater.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(arg_numMeasure)->m_CalibZeroWater.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}
QString CWinMaintenanceModel::sGetCoefSondeCalculeLbl(int arg_numMeasure)const
{
	QString sLbl = QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(arg_numMeasure)->m_CalibZeroWaterNew.szGetLabel()
    										 , m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(arg_numMeasure)->m_CalibZeroWaterNew.lGetLabelLength());
	//qDebug() << "ETALON" << sLbl;
	return sLbl;
}

//Set valeur des variables de mesure
void CWinMaintenanceModel::setMesureManuelleVal(const QString& sValue, int arg_numStream, int arg_numMeasure)
{
	
	m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueAfter.bSetVal(sValue.toFloat());
	
	QString section = QString("CStream")+ QString::number(arg_numStream)+ QString("_CMesure")+ QString::number(arg_numMeasure) ;
	CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_StandardValueAfter"), &m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueAfter);
	
}
void CWinMaintenanceModel::setOffsetActuelVal(const QString& sValue, int arg_numStream)
{
	//TCHAR szTrace[500];
	//Sauvegarder le coeff de toute les voies
#ifdef CALIBRATIONS_INDEPENDANTE
	QString section = QString("CStream")+ QString::number(arg_numStream)+ QString("_CMesure0") ;
    m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWater.bSetVal(sValue.toFloat());
    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibZeroWater")
           , &m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWater);
#else
    for(int i=0; i< m_pSupervision->getAnalyseur()->iGetNbrStream(); ++i)
    {
        QString section = QString("CStream")+ QString::number(i)+ QString("_CMesure0") ;
	    m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_CalibZeroWater.bSetVal(sValue.toFloat());
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibZeroWater")
               , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_CalibZeroWater);
#ifdef SONDE
        if(i>0)
        {
            m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_OpticalGain.bSetVal( m_pSupervision->getAnalyseur()->pGetAt(i-1)->pGetAt(0)->m_OpticalGain.nGetVal());
	        CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_OpticalGain")
                   , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_OpticalGain);

			m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_ZeroOpticalMeasurement.bSetVal(m_pSupervision->getAnalyseur()->pGetAt(i-1)->pGetAt(0)->m_ZeroOpticalMeasurement.fGetVal());
	        CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_ZeroOpticalMeasurement")
                   , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_ZeroOpticalMeasurement);

			m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_AbsorbanceValue.bSetVal( m_pSupervision->getAnalyseur()->pGetAt(i-1)->pGetAt(0)->m_AbsorbanceValue.fGetVal());
	        CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_AbsorbanceValue")
                   , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_AbsorbanceValue);

			m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_OpticalMeasurement.bSetVal(m_pSupervision->getAnalyseur()->pGetAt(i-1)->pGetAt(0)->m_OpticalMeasurement.fGetVal());
	        CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_OpticalMeasurement")
                   , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_OpticalMeasurement);
        }
		else // si i = 0
		{

			CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_OpticalGain")
                   , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_OpticalGain);
			CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_ZeroOpticalMeasurement")
                   , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_ZeroOpticalMeasurement);
			CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_AbsorbanceValue")
                   , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_AbsorbanceValue);
			CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_OpticalMeasurement")
                   , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_OpticalMeasurement);
		}
#endif
    }
#endif
	//TRACE_LOG_MSG(szTrace);

}
void CWinMaintenanceModel::setOffsetCalculeVal(const QString& sValue, int arg_numStream)
{
	m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWaterNew.bSetVal(sValue.toFloat());
	QString section = QString("CStream")+ QString::number(arg_numStream)+ QString("_CMesure0");
	
	CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibZeroWaterNew"), &m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_CalibZeroWaterNew);
}
void CWinMaintenanceModel::setEtalonRefVal(const QString& sValue, int arg_numStream, int arg_numMeasure)
{
	//TCHAR szTrace[500];
	
	m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueBefore.bSetVal(sValue.toFloat());
	//_stprintf(szTrace,_T("Check Val étalon : %g \n")
	//	, m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_StandardValueBefore.fGetVal());
	QString section = QString("CStream")+ QString::number(arg_numStream)+ QString("_CMesure")+QString::number(arg_numMeasure) ;
	CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_StandardValueBefore"), &m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_StandardValueBefore);
	//TRACE_LOG_MSG(szTrace);

}
void CWinMaintenanceModel::setCoefActuelVal(const QString& sValue, int arg_numStream, int arg_numMeasure)
{
	//TCHAR szTrace[500];
	
    //Sauvegarder le coeff de toute les voies
#ifdef CALIBRATIONS_INDEPENDANTE
#ifdef CERIUM // Si pas 4 voie plantage !
	
	QString section = QString("CStream")+ QString::number(arg_numStream)+ QString("_CMesure")+QString::number(arg_numMeasure) ;
	    m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeff.bSetVal(sValue.toFloat());
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibCoeff")
               , &m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeff);

	if(arg_numMeasure == 0 && m_pSupervision->getAnalyseur()->iGetNbrStream() == 4){
		QString section = QString("CStream3_CMesure")+QString::number(arg_numMeasure) ;
	    m_pSupervision->getAnalyseur()->pGetAt(3)->pGetAt(arg_numMeasure)->m_CalibCoeff.bSetVal(sValue.toFloat());
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibCoeff")
               , &m_pSupervision->getAnalyseur()->pGetAt(3)->pGetAt(arg_numMeasure)->m_CalibCoeff);
	}
#else
	QString section = QString("CStream")+ QString::number(arg_numStream)+ QString("_CMesure")+QString::number(arg_numMeasure) ;
	    m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeff.bSetVal(sValue.toFloat());
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibCoeff")
               , &m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeff);
#endif
	 
#else
    for(int i=0; i< m_pSupervision->getAnalyseur()->iGetNbrStream(); ++i)
    {
        QString section = QString("CStream")+ QString::number(i)+ QString("_CMesure")+QString::number(arg_numMeasure) ;
	    m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(arg_numMeasure)->m_CalibCoeff.bSetVal(sValue.toFloat());
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibCoeff")
               , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(arg_numMeasure)->m_CalibCoeff);
    }
#endif


}
void CWinMaintenanceModel::setCoefCalculeVal(const QString& sValue, int arg_numStream, int arg_numMeasure)
{
#ifdef CALIBRATIONS_INDEPENDANTE
	m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeffNew.bSetVal(sValue.toFloat());
	    QString section = QString("CStream")+ QString::number(arg_numStream)+ QString("_CMesure")+QString::number(arg_numMeasure) ;
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibCoeffNew"), &m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibCoeffNew);
	
	if(arg_numMeasure == 0 && m_pSupervision->getAnalyseur()->iGetNbrStream() == 4){
		QString section = QString("CStream3_CMesure")+QString::number(arg_numMeasure) ;
	    m_pSupervision->getAnalyseur()->pGetAt(3)->pGetAt(arg_numMeasure)->m_CalibCoeffNew.bSetVal(sValue.toFloat());
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibCoeffNew")
               , &m_pSupervision->getAnalyseur()->pGetAt(3)->pGetAt(arg_numMeasure)->m_CalibCoeffNew);
	}
#else
	for(int i=0; i< m_pSupervision->getAnalyseur()->iGetNbrStream(); ++i)
    {
	    m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(arg_numMeasure)->m_CalibCoeffNew.bSetVal(sValue.toFloat());
	    QString section = QString("CStream")+ QString::number(i)+ QString("_CMesure")+QString::number(arg_numMeasure) ;
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_CalibCoeffNew"), &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(arg_numMeasure)->m_CalibCoeffNew);
    }
#endif
}
void CWinMaintenanceModel::setV0Val(const QString& sValue) //KMnO4
{
	m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_CalibZeroAir.bSetVal(sValue.toFloat());
	CMesureModel::writeElemConfigIni(_T("CStream0_CMesure0"), _T("m_CalibZeroAir"), &m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_CalibZeroAir);

}
void CWinMaintenanceModel::setV2Val(const QString& sValue) //KMnO4
{

#ifdef KMNO4	
	m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Delta.bSetVal(sValue.toFloat());
	CMesureModel::writeElemConfigIni(_T("CStream0_CMesure0"), _T("m_Delta"), &m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_Delta);
#endif


}
void CWinMaintenanceModel::setIndicateurEauAirVal(const QString& sValue) 
{
    for(int i=0; i< m_pSupervision->getAnalyseur()->iGetNbrStream(); ++i)
    {
        QString section = QString("CStream")+ QString::number(i)+ QString("_CMesure0") ;
	    m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_AirWaterFlag.bSetVal(sValue.toFloat());
	    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16(), _T("m_AirWaterFlag")
               , &m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(0)->m_AirWaterFlag);
    }
}
void CWinMaintenanceModel::passerAnalyseurEnMaintenance()
{
	
    m_bEtatVoieAvantMaintenance = m_pSupervision->getAnalyseur()->pGetAt(0)->m_Active.ucGetVal();
    m_pSupervision->getAnalyseur()->pGetAt(0)->m_Active.bSetVal(true);
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(0);
	iSaveRemoteCtrl = m_pSupervision->getAnalyseur()->m_CmdRemoteControl.ucGetVal();
    m_pSupervision->getAnalyseur()->m_CmdRemoteControl.bSetVal(CSupervision::eREMOTE_SAV);
	
}

void CWinMaintenanceModel::retourAnalyseurDeMaintenance()
{

    m_pSupervision->getAnalyseur()->pGetAt(0)->m_Active.bSetVal(m_bEtatVoieAvantMaintenance);

	m_pSupervision->getAnalyseur()->m_CmdRemoteControl.bSetVal(iSaveRemoteCtrl);
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(0);
	m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.bSetVal(0);
}

void CWinMaintenanceModel::executeCalib(int arg_numStream)
{
	qDebug() << "CWinMaintenanceModel::executeCalib voie " << arg_numStream;
	m_pSupervision->getAnalyseur()->m_CmdCycleCalib.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleCalibInLine.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleCleanup.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleZero.bSetVal(0xFF);
	
	while(!m_pSupervision->getAnalyseur()->bAnalyseurStoped)
	{
		m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(0);
		m_pSupervision->getAnalyseur()->m_CmdPause.bSetVal(0);
		Sleep(200);
	}
	m_pSupervision->getAnalyseur()->m_CmdCycleCalib.bSetVal(arg_numStream);
	this->setStartTimerCycle();
	m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.bSetVal(1);
	/*TCHAR szTrace[500];
	_stprintf(szTrace,_T("*** Cmd Run : %d ; Cmd Stop end cycle: %d \n")
		, m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal()
		, m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal());

	TRACE_LOG_MSG(szTrace);*/
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(1);
}
void CWinMaintenanceModel::executeCalibInLine(int arg_numStream)
{
	qDebug() << "CWinMaintenanceModel::executeCalibInLine voie " << arg_numStream;
	m_pSupervision->getAnalyseur()->m_CmdCycleCalib.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleCalibInLine.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleCleanup.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleZero.bSetVal(0xFF);
	while(!m_pSupervision->getAnalyseur()->bAnalyseurStoped)
	{
		m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(0);
		m_pSupervision->getAnalyseur()->m_CmdPause.bSetVal(0);
		Sleep(100);
	}
	m_pSupervision->getAnalyseur()->m_CmdCycleCalibInLine.bSetVal(arg_numStream);
	this->setStartTimerCycle();
	m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.bSetVal(1);
	/*TCHAR szTrace[500];
	_stprintf(szTrace,_T("*** Cmd Run : %d ; Cmd Stop end cycle: %d \n")
		, m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal()
		, m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal());

	TRACE_LOG_MSG(szTrace);*/
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(1);
}
void CWinMaintenanceModel::executeCleanup(int arg_numStream)
{
	qDebug() << "CWinMaintenanceModel::executeCleanup voie " << arg_numStream;
	m_pSupervision->getAnalyseur()->m_CmdCycleCalib.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleCalibInLine.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleCleanup.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleZero.bSetVal(0xFF);
	while(!m_pSupervision->getAnalyseur()->bAnalyseurStoped)
	{
		m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(0);
		m_pSupervision->getAnalyseur()->m_CmdPause.bSetVal(0);
		Sleep(100);
	}
	m_pSupervision->getAnalyseur()->m_CmdCycleCleanup.bSetVal(arg_numStream);
	this->setStartTimerCycle();
	m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.bSetVal(1);
	/*TCHAR szTrace[500];
	_stprintf(szTrace,_T("*** Cmd Run : %d ; Cmd Stop end cycle: %d \n")
		, m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal()
		, m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal());

	TRACE_LOG_MSG(szTrace);*/
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(1);
}
void CWinMaintenanceModel::executeZero(int arg_numStream)
{
	qDebug() << "CWinMaintenanceModel::executeZero voie " << arg_numStream;
	m_pSupervision->getAnalyseur()->m_CmdCycleCalib.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleCalibInLine.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleCleanup.bSetVal(0xFF);
	m_pSupervision->getAnalyseur()->m_CmdCycleZero.bSetVal(0xFF);
	while(!m_pSupervision->getAnalyseur()->bAnalyseurStoped)
	{
		m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(0);
		m_pSupervision->getAnalyseur()->m_CmdPause.bSetVal(0);
		Sleep(100);
	}
	m_pSupervision->getAnalyseur()->m_CmdCycleZero.bSetVal(arg_numStream);
	this->setStartTimerCycle();
	m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.bSetVal(1);
	/*TCHAR szTrace[500];
	_stprintf(szTrace,_T("*** Cmd Run : %d ; Cmd Stop end cycle: %d \n")
		, m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal()
		, m_pSupervision->getAnalyseur()->m_CmdStopEndCycle.ucGetVal());

	TRACE_LOG_MSG(szTrace);*/
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(1);
}

//SLOT utilisé avec timer
void CWinMaintenanceModel::getDataFromSupervision()
{
    qDebug() << "CWinMaintenanceModel::getDataFromSupervision()";
	
	m_sNameStep = QString::fromUtf16(( const ushort *)CElemCycle::m_CurrentStep.szGetLabel()
												    , CElemCycle::m_CurrentStep.lGetLabelLength());
	m_iCurrentStep=CElemCycle::m_CurrentStep.m_Step.nGetVal();

	m_bRun=m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal();
	m_bStop = !m_bRun;
	m_bPause = m_pSupervision->getAnalyseur()->m_CmdPause.ucGetVal();
	if( m_pSupervision->getAnalyseur()->m_CmdCycleCalib.ucGetVal() == 0xFF
		&& m_pSupervision->getAnalyseur()->m_CmdCycleCalibInLine.ucGetVal() == 0xFF
		&& m_pSupervision->getAnalyseur()->m_CmdCycleZero.ucGetVal() == 0xFF
		&& m_pSupervision->getAnalyseur()->m_CmdCycleCleanup.ucGetVal() == 0xFF)
		m_timerCycle->stop();

	qDebug() << "getDataFromSupervision Maintenance. NameStep: " << m_sNameStep ;
}
QString CWinMaintenanceModel::getTemperatureCuve()
{
    qDebug() << "CWinMaintenanceModel::getTemperatureCuve()";
    CElemExchangeJbus *pElem;
	TCHAR szText[5000];
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	/*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve")
							,m_pSupervision->getCarteMesure()->getListExchange()
						    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fTemperatureCuve"));
	QString sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	QString sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	QString sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	QByteArray byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	qDebug() << sTemp1 << "  " << byteArray;
	int nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	qDebug() << sTemp1<< " bis " << byteArray;
	QByteArray byteArrayHex = byteArray.mid(nPos, 2);
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	byteArray = QByteArray::number(sTemp2.toLongLong(), 16);
	qDebug() << sTemp2 << "  " << byteArray;
	nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	qDebug() << sTemp1<< " bis " << byteArray;
	byteArrayHex.append(byteArray.mid(nPos, 2));
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	float tmp = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
	qDebug() << "fTemperatureCuve= "<< QString::number( tmp,'f', 5 );
    return QString::number( tmp, 'f', 2);
    qDebug() << "FIN CWinMaintenanceModel::getTemperatureCuve()";

}
QString CWinMaintenanceModel::getPressionEau(){
    qDebug() << "CWinMaintenanceModel::getPressionEau()";

    CElemExchangeJbus *pElem;
	TCHAR szText[5000];
     m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fPressionEau")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	/*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fPressionEau")
							,m_pSupervision->getCarteMesure()->getListExchange()
						    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fPressionEau"));
	QString sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	QString sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	QString sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	QByteArray byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	int nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	QByteArray byteArrayHex = byteArray.mid(nPos, 2);
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	byteArray = QByteArray::number(sTemp2.toLongLong(), 16);	
	nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	byteArrayHex.append(byteArray.mid(nPos, 2));
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	float tmp = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
    return QString::number( tmp, 'f', 2);
    qDebug() << "FIN CWinMaintenanceModel::getPressionEau()";

}

QString CWinMaintenanceModel::getMesureOptique(){
    qDebug() << "CWinMaintenanceModel::getMesureOptique()";

    CElemExchangeJbus *pElem;
	TCHAR szText[5000];
#ifdef SONDE
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fMesureElectrode")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fMesureElectrode"));
#else
    m_threadPool->start(new CCmdJBusRunnable( this
                                            , m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique")
                                            , m_pSupervision->getCarteMesure()->getListExchange()
                                            , m_pSupervision->getAnalyseur()->m_ExternalInterface));
	pElem =(CElemExchangeJbus*)m_pSupervision->getCarteMesure()->getListExchange()->pGetAt(m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique"));
#endif	
    /*m_cycleStep.bExecuteNumExchange(m_pSupervision->getNumRQTComJBUSMesure("fMesureOptique")
							,m_pSupervision->getCarteMesure()->getListExchange()
						    ,TRUE,TRUE , m_pSupervision->getAnalyseur()->m_ExternalInterface);*/
	QString sRQT = QString::fromUtf16((const ushort*)pElem->m_pTrameJbusRP->szGetConfig(szText, 5000));
	QString sTemp1 = sRQT.split("|").at(sRQT.split("|").count()-1);
	QString sTemp2 = sRQT.split("|").at(sRQT.split("|").count()-2);
	//qDebug() << sTemp1 << "  " << sTemp2;
	QByteArray byteArray = QByteArray::number(sTemp1.toLongLong(), 16);
	int nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	QByteArray byteArrayHex = byteArray.mid(nPos, 2);
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	byteArray = QByteArray::number(sTemp2.toLongLong(), 16);
	nPos=2;
	if(byteArray.count() > 4) nPos = byteArray.count()-2;
	else if(byteArray.count() < 4) for(; byteArray.count()<4; byteArray.prepend("0")); 
	byteArrayHex.append(byteArray.mid(nPos, 2));
	byteArrayHex.append(byteArray.mid(nPos-2,2));
	
    float tmp = CSupervision::getFloatFromQByteArrayHex(byteArrayHex);
    return QString::number( tmp, 'f', 2);
    qDebug() << "FIN CWinMaintenanceModel::getMesureOptique()";

}
//SLOT utilisé par le deuxième timer_diag
float CWinMaintenanceModel::getOpticalGainValue()const
{
	return m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.nGetVal();
}
QString CWinMaintenanceModel::getOpticalGainLbl()const
{
	return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.szGetLabel());

}
QString CWinMaintenanceModel::getOpticalGainUnit()const
{
	return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalGain.m_szUnit.szGetLabel());   
}
float CWinMaintenanceModel::getZeroOpticalMeasurementValue()const{
	return m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.fGetVal();
}
QString CWinMaintenanceModel::getZeroOpticalMeasurementLbl()const{
	return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.szGetLabel());
}
QString CWinMaintenanceModel::getZeroOpticalMeasurementUnit()const{
	return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_ZeroOpticalMeasurement.m_szUnit.szGetLabel());
}
QString CWinMaintenanceModel::getOpticalMeasurementLbl()const{
	return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.szGetLabel());
}
QString CWinMaintenanceModel::getOpticalMeasurementUnit()const{
	return QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.m_szUnit.szGetLabel());
}
float CWinMaintenanceModel::getOpticalMeasurementValue()const{
	return m_pSupervision->getAnalyseur()->pGetAt(0)->pGetAt(0)->m_OpticalMeasurement.fGetVal();
}
int CWinMaintenanceModel::getNbStream()const{
	return m_pSupervision->getAnalyseur()->iGetNbrStream();
}

//Méthode appelé par les thread de m_threadPool
void CWinMaintenanceModel::sendCmdJBus(const int& arg_numRQT, CElemList* arg_elemList, CEnumInterface& arg_interface)
{
    QMutexLocker locker(m_mutex);
    //qDebug() << "CWinMainModel::sendCmdJBus : " << arg_numRQT;
    m_cycleStep.bExecuteNumExchange(arg_numRQT, arg_elemList, TRUE, TRUE, arg_interface);
}
void CWinMaintenanceModel::setEnPause(bool bEnPause)
{
	if(bEnPause)
		m_pSupervision->getAnalyseur()->m_CmdPause.bSetVal(1);
	else
		m_pSupervision->getAnalyseur()->m_CmdPause.bSetVal(0);
}
bool CWinMaintenanceModel::getCycleMaintenanceEnCours()const
{
	if(   m_pSupervision->getAnalyseur()->m_CmdCycleCalib.ucGetVal() == 0xFF
	   && m_pSupervision->getAnalyseur()->m_CmdCycleCalibInLine.ucGetVal() == 0xFF
	   && m_pSupervision->getAnalyseur()->m_CmdCycleZero.ucGetVal() == 0xFF
	   && m_pSupervision->getAnalyseur()->m_CmdCycleCleanup.ucGetVal() == 0xFF)
		return false;
	else
		return true;
}
bool CWinMaintenanceModel::getCalibEnCours()const
{
	if(m_pSupervision->getAnalyseur()->m_CmdCycleCalib.ucGetVal() == 0xFF)
		return false;
	else
		return true;
}
bool CWinMaintenanceModel::getCalibInLineEnCours()const
{
	if(m_pSupervision->getAnalyseur()->m_CmdCycleCalibInLine.ucGetVal() == 0xFF)
		return false;
	else
		return true;
}
bool CWinMaintenanceModel::getZeroEnCours()const
{
	if(m_pSupervision->getAnalyseur()->m_CmdCycleZero.ucGetVal() == 0xFF)
		return false;
	else
		return true;
}
bool CWinMaintenanceModel::getCleanupEnCours()const
{
	if(m_pSupervision->getAnalyseur()->m_CmdCycleCleanup.ucGetVal() == 0xFF)
		return false;
	else
		return true;
}

void CWinMaintenanceModel::setConnexion()
{
    m_timerCycle = new QTimer(this);
	m_timerCycle->setInterval(1000);
	connect(m_timerCycle, SIGNAL(timeout()), this, SLOT(getDataFromSupervision()));
	//Signal de mise à jour à la vue
	connect(m_timerCycle, SIGNAL(timeout()), m_pView, SLOT(dataUpdate())); 

	m_timerDiag = new QTimer(this);
	m_timerDiag->setInterval(500);
	//Signal de mise à jour à la vue
	connect(m_timerDiag, SIGNAL(timeout()), m_pView, SLOT(dataUpdateDiag()));
}

void CWinMaintenanceModel::setStop()
{
    qDebug() << "CWinMaintenanceModel::setStop()";
	m_pSupervision->getAnalyseur()->m_CmdRun.bSetVal(0);
	m_bRun=m_pSupervision->getAnalyseur()->m_CmdRun.ucGetVal();
	m_bStop = !m_bRun;
	this->setStopTimerCycle();
	//m_sEtatAnalyseur = "EN ARRET";
    qDebug() << " FIN CWinMaintenanceModel::setStop()";

}
