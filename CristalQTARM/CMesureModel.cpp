#include "CMesureModel.h"

CMesureModel::CMesureModel(void)
{
	
}


QString CMesureModel::getVarMesureValeur(QString argsObjectName)
{
	TCHAR szText[250];
	bool convertionOk;
	//Base mis à 0 pour utiliser la convention du C soit dansnotre cas chaine qui commence par 0x convertion en hex
	long lIdVar = argsObjectName.toLong(&convertionOk, 0); 
	int iTypeVar = NUM_TYPE(lIdVar);
	QString sRetour;
	if(m_mapIdRefVar.contains(lIdVar))
	{
		switch(iTypeVar)
		{
			case eTYPE_INT8:
				sRetour = QString::number(((CElemInt8*)m_mapIdRefVar.value(lIdVar))->ucGetVal());
				break;
			case eTYPE_INT16:
				sRetour = QString::number(((CElemInt16*)m_mapIdRefVar.value(lIdVar))->nGetVal());
				break;
			case eTYPE_FLOAT:
				QString sPrecision = QString::fromUtf16(( const ushort *)((CElemFloat*)m_mapIdRefVar.value(lIdVar))->szGetConfig(szText, 250));
				sPrecision = sPrecision.split("|").last().split(".").last().left(1);
				sRetour = QString::number(((CElemFloat*)m_mapIdRefVar.value(lIdVar))->fGetVal(), 'f', sPrecision.toInt());
				break;
		}
	}
	else
		return "Unknow ID";
	return sRetour;
}
QString CMesureModel::getVarMesureLbl(QString argsObjectName)
{
	bool convertionOk;
	//Base mis à 0 pour utiliser la convention du C soit dansnotre cas chaine qui commence par 0x convertion en hex
	long lIdVar = argsObjectName.toLong(&convertionOk, 0); 
	if(m_mapIdRefVar.contains(lIdVar))
		return QString::fromUtf16(( const ushort *)m_mapIdRefVar.value(lIdVar)->szGetLabel()
											 , m_mapIdRefVar.value(lIdVar)->lGetLabelLength());
	else
		return "Unknow ID";
}
QString CMesureModel::getVarMesureUnit(QString argsObjectName)
{
	bool convertionOk;
	//Base mis à 0 pour utilisé la convention du C soit dansnotre cas chaine qui commence par 0x convertion en hex
	long lIdVar = argsObjectName.toLong(&convertionOk, 0); 
	
	if(m_mapIdRefVar.contains(lIdVar))
		return QString::fromUtf16(( const ushort *)m_mapIdRefVar.value(lIdVar)->m_szUnit.szGetLabel()
												 , m_mapIdRefVar.value(lIdVar)->m_szUnit.lGetLabelLength());
	else
		return "Unknow ID";
}
void CMesureModel::setVarMesureValeur(QString argsObjectName, QString argsObjectKey, QString arg_sValue)
{
	
	bool convertionOk;
	//Base mis à 0 pour utilisé la convention du C soit dansnotre cas chaine qui commence par 0x convertion en hex
	long lIdVar = argsObjectKey.toLong(&convertionOk, 0); 
	int iTypeVar = NUM_TYPE(lIdVar);
	QString sRetour;
	//qDebug() << "m_mapIdRefVar.contains(lIdVar) " << m_mapIdRefVar.contains(lIdVar);
	if(m_mapIdRefVar.contains(lIdVar))
	{
		qDebug() << "iTypeVar "<< iTypeVar ;
		switch(iTypeVar)
		{
			case eTYPE_INT8:
				((CElemInt8*)m_mapIdRefVar.value(lIdVar))->bSetVal((BYTE)arg_sValue.toShort(0, 10));
				break;
			case eTYPE_INT16:
				((CElemInt16*)m_mapIdRefVar.value(lIdVar))->bSetVal(arg_sValue.toInt(0, 10));
				break;
			case eTYPE_FLOAT:
				((CElemFloat*)m_mapIdRefVar.value(lIdVar))->bSetVal(arg_sValue.toFloat());
				break;
		}
		writeElemConfigIni(_T("CStream0_CMesure0")
							, (WCHAR *)argsObjectName.utf16()
							, m_mapIdRefVar.value(lIdVar));
		/*TRACE_LOG_MSG((WCHAR *)argsObjectName.utf16());
		TRACE_LOG_MSG(m_mapIdRefVar.value(lIdVar)->szGetConfig(szText3,MAX_PATH));*/
	}	
}

void CMesureModel::writeElemConfigIni(WCHAR* arg_szSection, WCHAR* arg_szElemName, CElemBase* arg_pCElemBase)
{
	TCHAR szText[260];
	TCHAR szText2[260];
	TCHAR szText3[260];
	
	_stprintf(szText,_T("config.ini"));
	szGetFullPathName(szText,szText2);
	bWritePrivateProfileString(arg_szSection
							, arg_szElemName
							, arg_pCElemBase->szGetConfig(szText3,MAX_PATH)
							, szGetFullPathName(szText,szText2));
}

void CMesureModel::initm_mapIdRefVar()
{
	m_mapIdRefVar.insert(m_pMesure->m_Val.iGetType(), &m_pMesure->m_Val); 
	m_mapIdRefVar.insert(m_pMesure->m_ValMax.iGetType(), &m_pMesure->m_ValMax); 
	m_mapIdRefVar.insert(m_pMesure->m_ValMin.iGetType(), &m_pMesure->m_ValMin); 
	m_mapIdRefVar.insert(m_pMesure->m_StatusFailure.iGetType(), &m_pMesure->m_StatusFailure); 
	m_mapIdRefVar.insert(m_pMesure->m_Threshold1.iGetType(), &m_pMesure->m_Threshold1); 
	m_mapIdRefVar.insert(m_pMesure->m_Threshold2.iGetType(), &m_pMesure->m_Threshold2); 
	m_mapIdRefVar.insert(m_pMesure->m_StatusThreshold1.iGetType(), &m_pMesure->m_StatusThreshold1); 
	m_mapIdRefVar.insert(m_pMesure->m_StatusThreshold2.iGetType(), &m_pMesure->m_StatusThreshold2); 
	m_mapIdRefVar.insert(m_pMesure->m_AnalogZero.iGetType(), &m_pMesure->m_AnalogZero); 
	m_mapIdRefVar.insert(m_pMesure->m_AnalogPlage.iGetType(), &m_pMesure->m_AnalogPlage); 
	m_mapIdRefVar.insert(m_pMesure->m_CalibCoeff.iGetType(), &m_pMesure->m_CalibCoeff); 
	m_mapIdRefVar.insert(m_pMesure->m_CalibZeroWater.iGetType(), &m_pMesure->m_CalibZeroWater); 
	m_mapIdRefVar.insert(m_pMesure->m_CalibZeroAir.iGetType(), &m_pMesure->m_CalibZeroAir); 
	m_mapIdRefVar.insert(m_pMesure->m_CalibStatusCoeff.iGetType(), &m_pMesure->m_CalibStatusCoeff); 
	m_mapIdRefVar.insert(m_pMesure->m_CalibStatusZero.iGetType(), &m_pMesure->m_CalibStatusZero); 
	m_mapIdRefVar.insert(m_pMesure->m_SettingThreshold.iGetType(), &m_pMesure->m_SettingThreshold); 
	m_mapIdRefVar.insert(m_pMesure->m_ValJbusSlave.iGetType(), &m_pMesure->m_ValJbusSlave); 
	m_mapIdRefVar.insert(m_pMesure->m_CoeffValJbusSlave.iGetType(), &m_pMesure->m_CoeffValJbusSlave); 
	m_mapIdRefVar.insert(m_pMesure->m_ValAna.iGetType(), &m_pMesure->m_ValAna); 
	m_mapIdRefVar.insert(m_pMesure->m_ValMaxConvertisseur.iGetType(), &m_pMesure->m_ValMaxConvertisseur); 
	m_mapIdRefVar.insert(m_pMesure->m_ValMinConvertisseur.iGetType(), &m_pMesure->m_ValMinConvertisseur); 
	m_mapIdRefVar.insert(m_pMesure->m_OpticalGain.iGetType(), &m_pMesure->m_OpticalGain); 
	m_mapIdRefVar.insert(m_pMesure->m_ZeroOpticalMeasurement.iGetType(), &m_pMesure->m_ZeroOpticalMeasurement); 
	m_mapIdRefVar.insert(m_pMesure->m_AbsorbanceValue.iGetType(), &m_pMesure->m_AbsorbanceValue); 
	m_mapIdRefVar.insert(m_pMesure->m_StandardValueBefore.iGetType(), &m_pMesure->m_StandardValueBefore); 
	m_mapIdRefVar.insert(m_pMesure->m_StandardValueAfter.iGetType(), &m_pMesure->m_StandardValueAfter); 
	m_mapIdRefVar.insert(m_pMesure->m_CalibCoeffNew.iGetType(), &m_pMesure->m_CalibCoeffNew); 
	m_mapIdRefVar.insert(m_pMesure->m_OpticalMeasurement.iGetType(), &m_pMesure->m_OpticalMeasurement); 
	m_mapIdRefVar.insert(m_pMesure->m_AbsorbanceReference.iGetType(), &m_pMesure->m_AbsorbanceReference); 
	m_mapIdRefVar.insert(m_pMesure->m_RawConcentration.iGetType(), &m_pMesure->m_RawConcentration); 
	m_mapIdRefVar.insert(m_pMesure->m_CorrectedAbsorbance.iGetType(), &m_pMesure->m_CorrectedAbsorbance); 
	m_mapIdRefVar.insert(m_pMesure->m_RealAbsorbance.iGetType(), &m_pMesure->m_RealAbsorbance); 
	m_mapIdRefVar.insert(m_pMesure->m_Delta.iGetType(), &m_pMesure->m_Delta); 
	m_mapIdRefVar.insert(m_pMesure->m_CalibZeroWaterNew.iGetType(), &m_pMesure->m_CalibZeroWaterNew); 
	m_mapIdRefVar.insert(m_pMesure->m_NumProgram.iGetType(), &m_pMesure->m_NumProgram); 


}