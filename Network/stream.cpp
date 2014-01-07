#include "stdafx.h"
#include "network.h"


enum eRemoteControl{
	eREMOTE_DEFAULT	= 0,
	eREMOTE_SAV	,			
	eREMOTE_JBUS_SLAVE,			
	eREMOTE_JBUS_MASTER	,			
};

/*(@!*****************************************************************************************
* Nom     : CStream
* Role    : definition d'une voie
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CStream::CStream(BYTE ucNumVoie):CElemBase(),m_ListPeriodicHourCycleCleanup(24), m_ListPeriodicHourCycleZero(24)
								,m_ListPeriodicHourCycleCalib(24),m_ListPeriodicHourCycleCalibInLine(24)
								,m_ListPeriodicDayCycleCleanup(7),m_ListPeriodicDayCycleZero(7)
								,m_ListPeriodicDayCycleCalib(7),m_ListPeriodicDayCycleCalibInLine(7)
{
	TCHAR szText[MAX_PATH];
	SYSTEMTIME  stTime;
	
	m_iType = MAKE_ID(ucNumVoie,0xFF,eTYPE_VOIE,0xEF);
	_stprintf(szText,_T("CStream n°%d"),ucNumVoie);
	SetLabel(szText);
	m_iNbrMesure = 0;
	memset(&m_apMesure[0],0,sizeof(m_apMesure));
	
	//Nom de la voie
	m_StreamName.SetLabel(_T("m_StreamName"));;
	m_StreamName.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_TXT,eID_STREAM_NAME));

	// temps de cycle
	m_CycleTimeMax.SetLabel(_T("m_CycleTimeMax"));;
	m_CycleTimeMax.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT16,eID_STREAM_CYCLE_TIME_MAX));
	// temps de cycle courant
	m_CycleTimeCurrent.SetLabel(_T("m_CycleTimeCurrent"));;
	m_CycleTimeCurrent.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT16,eID_STREAM_CYCLE_TIME_CURRENT));
	// actif
	m_Active.SetLabel(_T("m_Active"));;
	m_Active.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE));
	// m_StatusFailure
	m_StatusFailure.SetLabel(_T("m_StatusFailure"));;
	m_StatusFailure.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_STATUS_FAILURE));
	// m_StatusWaterFailure
	m_StatusWaterFailure.SetLabel(_T("m_StatusWaterFailure"));;
	m_StatusWaterFailure.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_STATUS_WATER_FAILURE));
	// m_IsRunning
	m_IsRunning.SetLabel(_T("m_IsRunning"));;
	m_IsRunning.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_IS_RUNNING));
	// m_CounterCycle
	m_CounterCycle.SetLabel(_T("m_CounterCycle"));;
	m_CounterCycle.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT16,eID_STREAM_COUNTER_CYCLE));
	
	
	// m_CellTemperature
	m_CellTemperature.SetLabel(_T("m_CellTemperature"));;
	m_CellTemperature.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_FLOAT,eID_STREAM_CELL_TEMPERATURE));
	// m_WaterFailureSetPoint
	m_WaterFailureSetPoint.SetLabel(_T("m_WaterFailureSetPoint"));;
	m_WaterFailureSetPoint.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_FLOAT,eID_STREAM_WATER_FAILURE_SET_POINT));
	// m_OpticalSetPoint
	m_OpticalSetPoint.SetLabel(_T("m_OpticalSetPoint"));;
	m_OpticalSetPoint.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT16,eID_STREAM_OPTICAL_SET_POINT));
	// m_CellTemperatureSetPoint
	m_CellTemperatureSetPoint.SetLabel(_T("m_CellTemperatureSetPoint"));;
	m_CellTemperatureSetPoint.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_FLOAT,eID_STREAM_CELL_TEMPERATURE_SET_POINT));
	// mesure pression 
	m_PressureMeasurement.SetLabel(_T("m_PressureMeasurement"));
	m_PressureMeasurement.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_FLOAT,eID_STREAM_PRESSURE_MEASUREMENT));

	m_ThresholdTemperatureProbe.SetLabel(_T("m_ThresholdTemperatureProbe"));
	m_ThresholdTemperatureProbe.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_FLOAT,eID_STREAM_THRESHOLD_TEMPERATURE_PROBE));

	m_TemperatureProbe.SetLabel(_T("m_TemperatureProbe"));
	m_TemperatureProbe.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_FLOAT,eID_STREAM_TEMPERATURE_PROBE));

	m_SettingColorThreshold1.SetLabel(_T("m_SettingColorThreshold1"));
	m_SettingColorThreshold1.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_FLOAT,eID_STREAM_SETTING_COLOR_THRESHOLD1)); 
	m_SettingColorThreshold2.SetLabel(_T("m_SettingColorThreshold2")); 
	m_SettingColorThreshold2.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_FLOAT,eID_STREAM_SETTING_COLOR_THRESHOLD2));

	m_PeriodicCycleCleanup.SetLabel(_T("m_PeriodicCycleCleanup")); 
	m_PeriodicCycleCleanup.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_PERIODIC_CYCLE_CLEANUP));
	m_PeriodicCycleZero.SetLabel(_T("m_PeriodicCycleZero")); 
	m_PeriodicCycleZero.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_PERIODIC_CYCLE_ZERO));
	m_PeriodicCycleCalib.SetLabel(_T("m_PeriodicCycleCalib"));
	m_PeriodicCycleCalib.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_PERIODIC_CYCLE_CALIB));
	m_PeriodicCycleCalibInLine.SetLabel(_T("m_PeriodicCycleCalibInLine"));
	m_PeriodicCycleCalibInLine.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_PERIODIC_CYCLE_CALIB_INLINE));

	m_ListPeriodicHourCycleCleanup.SetLabel(_T("m_ListPeriodicHourCycleCleanup")); 
	m_ListPeriodicHourCycleCleanup.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CLEANUP));
	m_ListPeriodicHourCycleZero.SetLabel(_T("m_ListPeriodicHourCycleZero")); 
	m_ListPeriodicHourCycleZero.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_ZERO));
	m_ListPeriodicHourCycleCalib.SetLabel(_T("m_ListPeriodicHourCycleCalib"));
	m_ListPeriodicHourCycleCalib.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CALIB));
	m_ListPeriodicHourCycleCalibInLine.SetLabel(_T("m_ListPeriodicHourCycleCalibInLine"));
	m_ListPeriodicHourCycleCalibInLine.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CALIB_INLINE));

	m_ListPeriodicDayCycleCleanup.SetLabel(_T("m_ListPeriodicDayCycleCleanup")); 
	m_ListPeriodicDayCycleCleanup.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CLEANUP));
	m_ListPeriodicDayCycleZero.SetLabel(_T("m_ListPeriodicDayCycleZero")); 
	m_ListPeriodicDayCycleZero.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_DAY_CYCLE_ZERO));
	m_ListPeriodicDayCycleCalib.SetLabel(_T("m_ListPeriodicDayCycleCalib"));
	m_ListPeriodicDayCycleCalib.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CALIB));
	m_ListPeriodicDayCycleCalibInLine.SetLabel(_T("m_ListPeriodicDayCycleCalibInLine"));
	m_ListPeriodicDayCycleCalibInLine.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CALIB_INLINE));

	m_ConditioningCycleCleanup.SetLabel(_T("m_ConditioningCycleCleanup")); 
	m_ConditioningCycleCleanup.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_CLEANUP));
	m_ConditioningCycleZero.SetLabel(_T("m_ConditioningCycleZero")); 
	m_ConditioningCycleZero.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_ZERO));
	m_ConditioningCycleCalib.SetLabel(_T("m_ConditioningCycleCalib"));
	m_ConditioningCycleCalib.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_CALIB));
	m_ConditioningCycleCalibInLine.SetLabel(_T("m_ConditioningCycleCalibInLine"));
	m_ConditioningCycleCalibInLine.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_CALIB_INLINE));
	m_ConditioningCycleMeasurement.SetLabel(_T("m_ConditioningCycleMeasurement"));
	m_ConditioningCycleMeasurement.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_MEASUREMENT));

	m_ConditioningCleanup.SetLabel(_T("m_ConditioningCleanup")); 
	m_ConditioningCleanup.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CLEANUP));
	m_ConditioningZero.SetLabel(_T("m_ConditioningZero")); 
	m_ConditioningZero.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_ZERO));
	m_ConditioningCalib.SetLabel(_T("m_ConditioningCalib"));
	m_ConditioningCalib.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CALIB));
	m_ConditioningCalibInLine.SetLabel(_T("m_ConditioningCalibInLine"));
	m_ConditioningCalibInLine.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CALIB_INLINE));
	m_ConditioningMeasurement.SetLabel(_T("m_ConditioningMeasurement"));
	m_ConditioningMeasurement.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_MEASUREMENT));

	m_StateConditioning.SetLabel(_T("m_StateConditioning"));
	m_StateConditioning.SetType(MAKE_ID(ucNumVoie,0xFF,eTYPE_INT8,eID_STREAM_STATE_CONDITIONING));

	m_iNbCycleCleanup=0;
	m_iNbCycleZero=0;
	m_iNbCycleCalib=0;
	m_iNbCycleCalibInLine=0;

	m_iNbConditioningCycleCleanup=0;
	m_iNbConditioningCycleZero=0;
	m_iNbConditioningCycleCalib=0;
	m_iNbConditioningCycleCalibInLine=0;

	GetLocalTime(&stTime);
	m_iCalibCheckedDays =stTime.wDayOfWeek;
	m_iCalibInLineCheckedDays=stTime.wDayOfWeek;
	m_iCleanupCheckedDays=stTime.wDayOfWeek;
	m_iZeroCheckedDays=stTime.wDayOfWeek;
	m_iCalibCheckedHours=stTime.wHour;
	m_iCalibInLineCheckedHours=stTime.wHour;
	m_iCleanupCheckedHours=stTime.wHour;
	m_iZeroCheckedHours=stTime.wHour;

	m_iCalibCheckedHours--;

}

CStream::~CStream()
{
	//TRACE_LOG_MSG(_T("ERREUR ZONE 12 Destruction de la voie"));
	RemoveAll();
}

void CStream::RemoveAll()
{
	// a supprimer en premier car contient des référence a CMesure 
	m_ElemCycle.RemoveAll();
	m_ElemCycleCleanup.RemoveAll();
	m_ElemCycleZero.RemoveAll();
	m_ElemCycleCalib.RemoveAll();
	m_ElemCycleCalibInLine.RemoveAll();
	// a supprimer à la fin 
	while (m_iNbrMesure-- > 0)
	{
		if (m_apMesure[m_iNbrMesure]) 
		{
			delete (m_apMesure[m_iNbrMesure]);
			m_apMesure[m_iNbrMesure] = NULL;
		}
	}
	m_iNbrMesure = 0;
}

CMesure *CStream::pNew()
{
	CMesure *pMesure = NULL;

	if (m_iNbrMesure < NBR_MESURE_MAX)
	{
		pMesure = new CMesure(NUM_VOIE(m_iType),(BYTE)m_iNbrMesure);
		if (pMesure)
		{
			m_apMesure[m_iNbrMesure] = pMesure;
			m_iNbrMesure++;
		}
	}
	return pMesure;
}

CMesure *CStream::pGetAt(int iPos)
{
	
	CMesure *pMesure = NULL;
	
	if ((iPos < m_iNbrMesure) && (iPos > -1))
	{
		
		pMesure = m_apMesure[iPos];
		
	}
	return pMesure;
}


BOOL CStream::bSerialize(CContext &Context)
{
	int i;
	BOOL bReturn = TRUE;

	bReturn = CElemBase::bSerialize(Context);

	if (bReturn) bReturn = m_CycleTimeMax.bSerialize(Context);
	if (bReturn) bReturn = m_StreamName.bSerialize(Context);
	if (bReturn) bReturn = m_CycleTimeCurrent.bSerialize(Context);
	if (bReturn) bReturn = m_Active.bSerialize(Context);
	if (bReturn) bReturn = m_StatusFailure.bSerialize(Context);
	if (bReturn) bReturn = m_StatusWaterFailure.bSerialize(Context);
	if (bReturn) bReturn = m_IsRunning.bSerialize(Context);
	if (bReturn) bReturn = m_CounterCycle.bSerialize(Context);

	if (bReturn) bReturn = bLoadSaveInt32(m_iNbrMesure,Context);

	for (i = 0;(bReturn) && (i < m_iNbrMesure);i++)
	{
		if (!Context.m_bSave) m_apMesure[i] = new CMesure(NUM_VOIE(m_iType),(BYTE)m_iNbrMesure);
		if (m_apMesure[i]) bReturn = m_apMesure[i]->bSerialize(Context);
	}

	if (bReturn) bReturn = m_ElemCycleFilename.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleCleanupFilename.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleZeroFilename.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleCalibFilename.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleCalibInLineFilename.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycle.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleCleanup.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleZero.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleCalib.bSerialize(Context);
	if (bReturn) bReturn = m_ElemCycleCalibInLine.bSerialize(Context);

	if (bReturn) bReturn = m_CellTemperature.bSerialize(Context);
	if (bReturn) bReturn = m_WaterFailureSetPoint.bSerialize(Context);
	if (bReturn) bReturn = m_OpticalSetPoint.bSerialize(Context);
	if (bReturn) bReturn = m_CellTemperatureSetPoint.bSerialize(Context);
	// mesure pression 
	if (bReturn) bReturn = m_PressureMeasurement.bSerialize(Context);
	if (bReturn) bReturn = m_ThresholdTemperatureProbe.bSerialize(Context); 
	if (bReturn) bReturn = m_TemperatureProbe.bSerialize(Context);
	if (bReturn) bReturn = m_SettingColorThreshold1.bSerialize(Context);
	if (bReturn) bReturn = m_SettingColorThreshold2.bSerialize(Context); 
	if (bReturn) bReturn = m_PeriodicCycleCleanup.bSerialize(Context); 
	if (bReturn) bReturn = m_PeriodicCycleZero.bSerialize(Context);
	if (bReturn) bReturn = m_PeriodicCycleCalib.bSerialize(Context);
	if (bReturn) bReturn = m_PeriodicCycleCalibInLine.bSerialize(Context);
	if (bReturn) bReturn = m_ListPeriodicHourCycleCleanup.bSerialize(Context); 
	if (bReturn) bReturn = m_ListPeriodicHourCycleZero.bSerialize(Context);
	if (bReturn) bReturn = m_ListPeriodicHourCycleCalib.bSerialize(Context);
	if (bReturn) bReturn = m_ListPeriodicHourCycleCalibInLine.bSerialize(Context);
	if (bReturn) bReturn = m_ListPeriodicDayCycleCleanup.bSerialize(Context); 
	if (bReturn) bReturn = m_ListPeriodicDayCycleZero.bSerialize(Context);
	if (bReturn) bReturn = m_ListPeriodicDayCycleCalib.bSerialize(Context);
	if (bReturn) bReturn = m_ListPeriodicDayCycleCalibInLine.bSerialize(Context);
	if (bReturn) bReturn = m_ConditioningCycleCleanup.bSerialize(Context); 
	if (bReturn) bReturn = m_ConditioningCycleZero.bSerialize(Context);
	if (bReturn) bReturn = m_ConditioningCycleCalib.bSerialize(Context);
	if (bReturn) bReturn = m_ConditioningCycleCalibInLine.bSerialize(Context);
	if (bReturn) bReturn = m_ConditioningCycleMeasurement.bSerialize(Context);
	if (bReturn) bReturn = m_ConditioningCleanup.bSerialize(Context); 
	if (bReturn) bReturn = m_ConditioningZero.bSerialize(Context);
	if (bReturn) bReturn = m_ConditioningCalib.bSerialize(Context);
	if (bReturn) bReturn = m_ConditioningCalibInLine.bSerialize(Context);
	if (bReturn) bReturn = m_ConditioningMeasurement.bSerialize(Context);
	if (bReturn) bReturn = m_StateConditioning.bSerialize(Context);

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		m_StatusFailure.bSetVal(1);
	}
	return bReturn;
}

int CStream::iGetStreamSize(CContext &Context)
{
	int i;
	int iSize = 0;

	iSize = CElemBase::iGetStreamSize(Context);
	iSize += m_StreamName.iGetStreamSize(Context);
	iSize += m_CycleTimeMax.iGetStreamSize(Context);
	iSize += m_CycleTimeCurrent.iGetStreamSize(Context);
	iSize += m_Active.iGetStreamSize(Context);
	iSize += m_StatusFailure.iGetStreamSize(Context);
	iSize += m_StatusWaterFailure.iGetStreamSize(Context);
	iSize += m_IsRunning.iGetStreamSize(Context);
	iSize += m_CounterCycle.iGetStreamSize(Context);

	iSize += sizeof(m_iNbrMesure);
	for (i = 0;i < m_iNbrMesure;i++)
	{
		if (m_apMesure[i]) iSize += m_apMesure[i]->iGetStreamSize(Context);
	}
	iSize += m_ElemCycleFilename.iGetStreamSize(Context);
	iSize += m_ElemCycleCleanup.iGetStreamSize(Context);
	iSize += m_ElemCycleZeroFilename.iGetStreamSize(Context);
	iSize += m_ElemCycleCalibFilename.iGetStreamSize(Context);
	iSize += m_ElemCycleCalibInLineFilename.iGetStreamSize(Context);
	iSize += m_ElemCycle.iGetStreamSize(Context);
	iSize += m_ElemCycleCleanup.iGetStreamSize(Context);
	iSize += m_ElemCycleZero.iGetStreamSize(Context);
	iSize += m_ElemCycleCalib.iGetStreamSize(Context);
	iSize += m_ElemCycleCalibInLine.iGetStreamSize(Context);

	iSize += m_CellTemperature.iGetStreamSize(Context);
	iSize += m_WaterFailureSetPoint.iGetStreamSize(Context);
	iSize += m_OpticalSetPoint.iGetStreamSize(Context);
	iSize += m_CellTemperatureSetPoint.iGetStreamSize(Context);
	// mesure pression 
	iSize += m_PressureMeasurement.iGetStreamSize(Context);
	iSize += m_ThresholdTemperatureProbe.iGetStreamSize(Context);
	iSize += m_TemperatureProbe.iGetStreamSize(Context);
	iSize += m_SettingColorThreshold1.iGetStreamSize(Context);
	iSize += m_SettingColorThreshold2.iGetStreamSize(Context); 
	iSize += m_PeriodicCycleCleanup.iGetStreamSize(Context); 
	iSize += m_PeriodicCycleZero.iGetStreamSize(Context);
	iSize += m_PeriodicCycleCalib.iGetStreamSize(Context);
	iSize += m_PeriodicCycleCalibInLine.iGetStreamSize(Context);
	iSize += m_ListPeriodicHourCycleCleanup.iGetStreamSize(Context); 
	iSize += m_ListPeriodicHourCycleZero.iGetStreamSize(Context);
	iSize += m_ListPeriodicHourCycleCalib.iGetStreamSize(Context);
	iSize += m_ListPeriodicHourCycleCalibInLine.iGetStreamSize(Context);
	iSize += m_ListPeriodicDayCycleCleanup.iGetStreamSize(Context); 
	iSize += m_ListPeriodicDayCycleZero.iGetStreamSize(Context);
	iSize += m_ListPeriodicDayCycleCalib.iGetStreamSize(Context);
	iSize += m_ListPeriodicDayCycleCalibInLine.iGetStreamSize(Context);
	iSize += m_ConditioningCycleCleanup.iGetStreamSize(Context); 
	iSize += m_ConditioningCycleZero.iGetStreamSize(Context);
	iSize += m_ConditioningCycleCalib.iGetStreamSize(Context);
	iSize += m_ConditioningCycleCalibInLine.iGetStreamSize(Context);
	iSize += m_ConditioningCycleMeasurement.iGetStreamSize(Context);
	iSize += m_ConditioningCleanup.iGetStreamSize(Context); 
	iSize += m_ConditioningZero.iGetStreamSize(Context);
	iSize += m_ConditioningCalib.iGetStreamSize(Context);
	iSize += m_ConditioningCalibInLine.iGetStreamSize(Context);
	iSize += m_ConditioningMeasurement.iGetStreamSize(Context);
	iSize += m_StateConditioning.iGetStreamSize(Context);

	return iSize;
}


BOOL CStream::bReadConfig(int iNumStream, LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn = TRUE;
	int i;
	int iNbrMesure;
	TCHAR szRub[MAX_PATH];
	TCHAR szText[MAX_PATH];
	TCHAR szText2[MAX_PATH];
	CMesure *pMesure;
	CElemBase* pElem;

	_stprintf(szRub,_T("CStream%d"),iNumStream);
	// Nom de la voie 
//	_stprintf(szText2,_T("0x%08x|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_TXT,eID_STREAM_NAME),m_StreamName.m_szFormat.szGetLabel());
//	dwGetPrivateProfileString(szRub,_T("m_StreamName"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
//	m_StreamName.bSetConfig(szText);

	// temps de cycle max
	_stprintf(szText2,_T("0x%08x|CycleTimeMax|100.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_INT16,eID_STREAM_CYCLE_TIME_MAX),m_CycleTimeMax.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CycleTimeMax"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CycleTimeMax.bSetConfig(szText);
	// temps de cycle courant
	_stprintf(szText2,_T("0x%08x|CycleTimeCurrent|0.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_INT16,eID_STREAM_CYCLE_TIME_CURRENT),m_CycleTimeCurrent.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CycleTimeCurrent"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CycleTimeCurrent.bSetConfig(szText);
	m_CycleTimeCurrent.bSetVal(0);
	// etat actif
	_stprintf(szText2,_T("0x%08x|Active|1.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_INT8,eID_STREAM_ACTIVE),m_Active.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Active"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Active.bSetConfig(szText);
	// Status Failure
	_stprintf(szText2,_T("0x%08x|StatusFailure|0.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_INT8,eID_STREAM_STATUS_FAILURE),m_StatusFailure.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StatusFailure"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StatusFailure.bSetConfig(szText);
	m_StatusFailure.bSetVal(0);
	// Status water Failure
	_stprintf(szText2,_T("0x%08x|StatusWaterFailure|0.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_INT8,eID_STREAM_STATUS_WATER_FAILURE),m_StatusWaterFailure.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StatusWaterFailure"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StatusWaterFailure.bSetConfig(szText);
	m_StatusWaterFailure.bSetVal(0);

	// m_IsRunning
	_stprintf(szText2,_T("0x%08x|m_IsRunning|0|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_INT8,eID_STREAM_IS_RUNNING),m_IsRunning.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_IsRunning"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_IsRunning.bSetConfig(szText);
	m_IsRunning.bSetVal(0);
	// m_CounterCycle
	_stprintf(szText2,_T("0x%08x|m_CounterCycle|0|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_INT16,eID_STREAM_COUNTER_CYCLE),m_CounterCycle.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CounterCycle"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CounterCycle.bSetConfig(szText);
	m_CounterCycle.bSetVal(0);

	iNbrMesure = iGetPrivateProfileInt(szRub,_T("m_iNbrMesure"),NBR_MESURE_MAX,pszFileName);
//	for (i = 0; bReturn && (i < NBR_MESURE_MAX /*iNbrMesure*/); i++)
	for (i = 0; bReturn && (i < iNbrMesure); i++)
	{
		pMesure = pGetAt(i);
		if (pMesure == NULL) pMesure = pNew();
		if (pMesure)
		{
			bReturn = pMesure->bReadConfig(iNumStream,i,pszFileName);
		}
	}


	// m_CellTemperature
	_stprintf(szText2,_T("0x%08x|m_CellTemperature|1.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_FLOAT,eID_STREAM_CELL_TEMPERATURE),m_CellTemperature.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CellTemperature"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CellTemperature.bSetConfig(szText);
	// m_WaterFailureSetPoint
	_stprintf(szText2,_T("0x%08x|m_WaterFailureSetPoint|1.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_FLOAT,eID_STREAM_WATER_FAILURE_SET_POINT),m_WaterFailureSetPoint.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_WaterFailureSetPoint"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_WaterFailureSetPoint.bSetConfig(szText);
	// m_OpticalSetPoint
	_stprintf(szText2,_T("0x%08x|m_OpticalSetPoint|1.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_INT16,eID_STREAM_OPTICAL_SET_POINT),m_OpticalSetPoint.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_OpticalSetPoint"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_OpticalSetPoint.bSetConfig(szText);
	// m_CellTemperatureSetPoint
	_stprintf(szText2,_T("0x%08x|m_CellTemperatureSetPoint|1.|.|%s"),MAKE_ID(iNumStream,0xFF,eTYPE_FLOAT,eID_STREAM_CELL_TEMPERATURE_SET_POINT),m_CellTemperatureSetPoint.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CellTemperatureSetPoint"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CellTemperatureSetPoint.bSetConfig(szText);
	// mesure pression 
	_stprintf(szText2,_T("0x%08x|m_PressureMeasurement|1.|mV|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_FLOAT,eID_STREAM_PRESSURE_MEASUREMENT),m_PressureMeasurement.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_PressureMeasurement"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_PressureMeasurement.bSetConfig(szText);

	_stprintf(szText2,_T("0x%08x|m_ThresholdTemperatureProbe|1.|mV|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_FLOAT,eID_STREAM_THRESHOLD_TEMPERATURE_PROBE),m_ThresholdTemperatureProbe.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ThresholdTemperatureProbe"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ThresholdTemperatureProbe.bSetConfig(szText); 

	_stprintf(szText2,_T("0x%08x|m_TemperatureProbe|1.|mV|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_FLOAT,eID_STREAM_TEMPERATURE_PROBE),m_TemperatureProbe.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_TemperatureProbe"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_TemperatureProbe.bSetConfig(szText);

	_stprintf(szText2,_T("0x%08x|m_SettingColorThreshold1|1.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_FLOAT,eID_STREAM_SETTING_COLOR_THRESHOLD1),m_SettingColorThreshold1.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_SettingColorThreshold1"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_SettingColorThreshold1.bSetConfig(szText); 
	_stprintf(szText2,_T("0x%08x|m_SettingColorThreshold2|1.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_FLOAT,eID_STREAM_SETTING_COLOR_THRESHOLD2),m_SettingColorThreshold2.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_SettingColorThreshold2"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_SettingColorThreshold2.bSetConfig(szText); 

	_stprintf(szText2,_T("0x%08x|m_PeriodicCycleCleanup|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_PERIODIC_CYCLE_CLEANUP),m_PeriodicCycleCleanup.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_PeriodicCycleCleanup"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_PeriodicCycleCleanup.bSetConfig(szText); 
	_stprintf(szText2,_T("0x%08x|m_PeriodicCycleZero|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_PERIODIC_CYCLE_ZERO),m_PeriodicCycleZero.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_PeriodicCycleZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_PeriodicCycleZero.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_PeriodicCycleCalib|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_PERIODIC_CYCLE_CALIB),m_PeriodicCycleCalib.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_PeriodicCycleCalib"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_PeriodicCycleCalib.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_PeriodicCycleCalibInLine|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_PERIODIC_CYCLE_CALIB_INLINE),m_PeriodicCycleCalibInLine.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_PeriodicCycleCalibInLine"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_PeriodicCycleCalibInLine.bSetConfig(szText);


	//Init des listes pour les periodiques
	for (i = 0; i < 24;i++) //Liste de 24 heures 
	{
		if (m_ListPeriodicHourCycleCleanup.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListPeriodicHourCycleCleanup.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
		if (m_ListPeriodicHourCycleZero.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListPeriodicHourCycleZero.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
		if (m_ListPeriodicHourCycleCalib.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListPeriodicHourCycleCalib.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
		if (m_ListPeriodicHourCycleCalibInLine.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListPeriodicHourCycleCalibInLine.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
	}
	_stprintf(szText2,_T("0x%x|m_ListPeriodicHourCycleCleanup|0|1|2|3"),MAKE_ID(iNumStream, 0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CLEANUP));
	dwGetPrivateProfileString(szRub,_T("m_ListPeriodicHourCycleCleanup"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListPeriodicHourCycleCleanup.bSetConfig(szText); 
	_stprintf(szText2,_T("0x%08x|m_ListPeriodicHourCycleZero|0|1|2|3"),MAKE_ID(iNumStream, 0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_ZERO));
	dwGetPrivateProfileString(szRub,_T("m_ListPeriodicHourCycleZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListPeriodicHourCycleZero.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ListPeriodicHourCycleCalib|0|0|0|0|0|0|0|0|0|1|1|0|0|1|0|1|0|1|0|0|0|0|0|0"),MAKE_ID(iNumStream, 0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CALIB));
	dwGetPrivateProfileString(szRub,_T("m_ListPeriodicHourCycleCalib"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListPeriodicHourCycleCalib.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ListPeriodicHourCycleCalibInLine|0|1|2|3"),MAKE_ID(iNumStream, 0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CALIB_INLINE));
	dwGetPrivateProfileString(szRub,_T("m_ListPeriodicHourCycleCalibInLine"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListPeriodicHourCycleCalibInLine.bSetConfig(szText);
	
	for (i = 0; i < 7;i++) //Liste de 7 jours 
	{
		if (m_ListPeriodicDayCycleCleanup.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListPeriodicDayCycleCleanup.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
		if (m_ListPeriodicDayCycleZero.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListPeriodicDayCycleZero.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
		if (m_ListPeriodicDayCycleCalib.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListPeriodicDayCycleCalib.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
		if (m_ListPeriodicDayCycleCalibInLine.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListPeriodicDayCycleCalibInLine.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
	}
	_stprintf(szText2,_T("0x%08x|m_ListPeriodicDayCycleCleanup|0|1|2|3"),MAKE_ID(iNumStream, 0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CLEANUP));
	dwGetPrivateProfileString(szRub,_T("m_ListPeriodicDayCycleCleanup"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListPeriodicDayCycleCleanup.bSetConfig(szText); 
	_stprintf(szText2,_T("0x%08x|m_ListPeriodicDayCycleZero|0|1|2|3"),MAKE_ID(iNumStream, 0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_DAY_CYCLE_ZERO));
	dwGetPrivateProfileString(szRub,_T("m_ListPeriodicDayCycleZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListPeriodicDayCycleZero.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ListPeriodicDayCycleCalib|0|1|0|1|0|1|0"),MAKE_ID(iNumStream, 0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CALIB));
	dwGetPrivateProfileString(szRub,_T("m_ListPeriodicDayCycleCalib"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListPeriodicDayCycleCalib.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ListPeriodicDayCycleCalibInLine|0|1|2|3"),MAKE_ID(iNumStream, 0xFF,eTYPE_LIST,eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CALIB_INLINE));
	dwGetPrivateProfileString(szRub,_T("m_ListPeriodicDayCycleCalibInLine"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListPeriodicDayCycleCalibInLine.bSetConfig(szText);

	_stprintf(szText2,_T("0x%08x|m_ConditioningCycleCleanup|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_CLEANUP),m_ConditioningCycleCleanup.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningCycleCleanup"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningCycleCleanup.bSetConfig(szText); 
	_stprintf(szText2,_T("0x%08x|m_ConditioningCycleZero|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_ZERO),m_ConditioningCycleZero.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningCycleZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningCycleZero.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ConditioningCycleCalib|0|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_CALIB),m_ConditioningCycleCalib.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningCycleCalib"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningCycleCalib.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ConditioningCycleCalibInLine|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_CALIB_INLINE),m_ConditioningCycleCalibInLine.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningCycleCalibInLine"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningCycleCalibInLine.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ConditioningCycleMeasurement|0|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CYCLE_MEASUREMENT),m_ConditioningCycleMeasurement.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningCycleMeasurement"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningCycleMeasurement.bSetConfig(szText);
	
	_stprintf(szText2,_T("0x%08x|m_ConditioningCleanup|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CLEANUP),m_ConditioningCleanup.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningCleanup"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningCleanup.bSetConfig(szText); 
	_stprintf(szText2,_T("0x%08x|m_ConditioningZero|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_ZERO),m_ConditioningZero.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningZero.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ConditioningCalib|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CALIB),m_ConditioningCalib.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningCalib"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningCalib.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ConditioningCalibInLine|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_CALIB_INLINE),m_ConditioningCalibInLine.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningCalibInLine"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningCalibInLine.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|m_ConditioningMeasurement|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_CONDITIONING_MEASUREMENT),m_ConditioningMeasurement.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ConditioningMeasurement"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ConditioningMeasurement.bSetConfig(szText);
	
	_stprintf(szText2,_T("0x%08x|m_StateConditioning|0.|.|%s"),MAKE_ID(iNumStream, 0xFF,eTYPE_INT8,eID_STREAM_STATE_CONDITIONING),m_StateConditioning.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StateConditioning"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StateConditioning.bSetConfig(szText);
	
	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		m_StatusFailure.bSetVal(1);
	}
	return bReturn;
}


BOOL CStream::bReadCycle(int iNumStream, LPCTSTR pszFileName,CListStream *pListStream)
{
	BOOL bReturn = TRUE;
	TCHAR szRub[MAX_PATH];
	TCHAR szText[MAX_PATH];

	_stprintf(szRub,_T("CStream%d"),iNumStream);

	// m_ElemCycleFilenamee
	dwGetPrivateProfileString(szRub,_T("m_ElemCycleFilename"),_T("cycle.ini"),szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ElemCycleFilename.SetLabel(szText);

	// m_ElemCycleCleanupFilename
	dwGetPrivateProfileString(szRub,_T("m_ElemCycleCleanupFilename"),_T("cyclecleanup.ini"),szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ElemCycleCleanupFilename.SetLabel(szText);
	// m_ElemCycleZeroFilename
	dwGetPrivateProfileString(szRub,_T("m_ElemCycleZeroFilename"),_T("cyclezero.ini"),szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ElemCycleZeroFilename.SetLabel(szText);

	// m_ElemCycleCalibFilename
	dwGetPrivateProfileString(szRub,_T("m_ElemCycleCalibFilename"),_T("cyclecalib.ini"),szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ElemCycleCalibFilename.SetLabel(szText);

	// m_ElemCycle2CalibFilename
	dwGetPrivateProfileString(szRub,_T("m_ElemCycleCalibInLineFilename"),_T("cyclecalib2.ini"),szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ElemCycleCalibInLineFilename.SetLabel(szText);

	// lecture des config 
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(m_ElemCycleFilename.szGetLabel(),szText),SZ_FIC_TEMP2,FALSE);
	if (bReturn) bReturn = m_ElemCycle.bReadConfig(SZ_FIC_TEMP2,pListStream);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(m_ElemCycleCleanupFilename.szGetLabel(),szText),SZ_FIC_TEMP2,FALSE);
	if (bReturn) bReturn = m_ElemCycleCleanup.bReadConfig(SZ_FIC_TEMP2,pListStream);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(m_ElemCycleZeroFilename.szGetLabel(),szText),SZ_FIC_TEMP2,FALSE);
	if (bReturn) bReturn = m_ElemCycleZero.bReadConfig(SZ_FIC_TEMP2,pListStream);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(m_ElemCycleCalibFilename.szGetLabel(),szText),SZ_FIC_TEMP2,FALSE);
	if (bReturn) bReturn = m_ElemCycleCalib.bReadConfig(SZ_FIC_TEMP2,pListStream);
	if (bReturn) bReturn = bCopyFile(szGetFullPathName(m_ElemCycleCalibInLineFilename.szGetLabel(),szText),SZ_FIC_TEMP2,FALSE);
	if (bReturn) bReturn = m_ElemCycleCalibInLine.bReadConfig(SZ_FIC_TEMP2,pListStream);

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		m_StatusFailure.bSetVal(1);
	}
	return bReturn;
}



BOOL CStream::bWriteConfig(int iNumStream,LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;
	int i;
	TCHAR szRub[MAX_PATH];
	TCHAR szText[MAX_PATH];
	CMesure *pMesure;

	_stprintf(szRub,_T("CStream%d"),iNumStream);
	
	// temps de cycle max
	bReturn = bWritePrivateProfileString(szRub,_T("m_CycleTimeMax"),m_CycleTimeMax.szGetConfig(szText,MAX_PATH),pszFileName);
	//Nom de la voie 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StreamName"),m_StreamName.szGetConfig(szText,MAX_PATH),pszFileName);
	// temps de cycle courant
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CycleTimeCurrent"),m_CycleTimeCurrent.szGetConfig(szText,MAX_PATH),pszFileName);
	// actif
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Active"),m_Active.szGetConfig(szText,MAX_PATH),pszFileName);
	// status failure
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StatusFailure"),m_StatusFailure.szGetConfig(szText,MAX_PATH),pszFileName);
	// status water failure
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StatusWaterFailure"),m_StatusWaterFailure.szGetConfig(szText,MAX_PATH),pszFileName);
	// is runnung
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_IsRunning"),m_IsRunning.szGetConfig(szText,MAX_PATH),pszFileName);
	// m_CounterCycle
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CounterCycle"),m_CounterCycle.szGetConfig(szText,MAX_PATH),pszFileName);


	bReturn = bWritePrivateProfileInt(szRub,_T("m_iNbrMesure"),iGetNbrMesure(),pszFileName);
	for (i = 0; bReturn && (i < iGetNbrMesure()); i++)
	{
		pMesure = pGetAt(i);
		bReturn = (pMesure != NULL);
		if (bReturn)
		{
			bReturn = pMesure->bWriteConfig(iNumStream,i,pszFileName);
		}
	}


	// m_ElemCycleFilenamee
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ElemCycleFilename"),m_ElemCycleFilename.szGetLabel(),pszFileName);

	// m_ElemCycleCleanupFilename
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ElemCycleCleanupFilename"),m_ElemCycleCleanupFilename.szGetLabel(),pszFileName);
	// m_ElemCycleZeroFilename
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ElemCycleZeroFilename"),m_ElemCycleZeroFilename.szGetLabel(),pszFileName);

	// m_ElemCycleCalibFilename
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ElemCycleCalibFilename"),m_ElemCycleCalibFilename.szGetLabel(),pszFileName);
	// m_ElemCycleCalibInLineFilename
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ElemCycleCalibInLineFilename"),m_ElemCycleCalibInLineFilename.szGetLabel(),pszFileName);

	
	// m_CellTemperature  
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CellTemperature"),m_CellTemperature.szGetConfig(szText,MAX_PATH),pszFileName);
	// m_WaterFailureSetPoint
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_WaterFailureSetPoint"),m_WaterFailureSetPoint.szGetConfig(szText,MAX_PATH),pszFileName);
	// m_OpticalSetPoint
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_OpticalSetPoint"),m_OpticalSetPoint.szGetConfig(szText,MAX_PATH),pszFileName);
	// m_CellTemperatureSetPoint
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CellTemperatureSetPoint"),m_CellTemperatureSetPoint.szGetConfig(szText,MAX_PATH),pszFileName);
	// mesure pression 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_PressureMeasurement"),m_PressureMeasurement.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ThresholdTemperatureProbe"),m_ThresholdTemperatureProbe.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_TemperatureProbe"),m_TemperatureProbe.szGetConfig(szText,MAX_PATH),pszFileName);
	//Configuration de la couleur des seuils
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_SettingColorThreshold1"),m_SettingColorThreshold1.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_SettingColorThreshold2"),m_SettingColorThreshold2.szGetConfig(szText,MAX_PATH),pszFileName);
	
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_PeriodicCycleCleanup"),m_PeriodicCycleCleanup.szGetConfig(szText,MAX_PATH),pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_PeriodicCycleZero"),m_PeriodicCycleZero.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_PeriodicCycleCalib"),m_PeriodicCycleCalib.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_PeriodicCycleCalibInLine"),m_PeriodicCycleCalibInLine.szGetConfig(szText,MAX_PATH),pszFileName);
	
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListPeriodicHourCycleCleanup"),m_ListPeriodicHourCycleCleanup.szGetConfig(szText,MAX_PATH),pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListPeriodicHourCycleZero"),m_ListPeriodicHourCycleZero.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListPeriodicHourCycleCalib"),m_ListPeriodicHourCycleCalib.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListPeriodicHourCycleCalibInLine"),m_ListPeriodicHourCycleCalibInLine.szGetConfig(szText,MAX_PATH),pszFileName);
	
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListPeriodicDayCycleCleanup"),m_ListPeriodicDayCycleCleanup.szGetConfig(szText,MAX_PATH),pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListPeriodicDayCycleZero"),m_ListPeriodicDayCycleZero.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListPeriodicDayCycleCalib"),m_ListPeriodicDayCycleCalib.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListPeriodicDayCycleCalibInLine"),m_ListPeriodicDayCycleCalibInLine.szGetConfig(szText,MAX_PATH),pszFileName);
	
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningCycleCleanup"),m_ConditioningCycleCleanup.szGetConfig(szText,MAX_PATH),pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningCycleZero"),m_ConditioningCycleZero.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningCycleCalib"),m_ConditioningCycleCalib.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningCycleCalibInLine"),m_ConditioningCycleCalibInLine.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningCycleMeasurement"),m_ConditioningCycleMeasurement.szGetConfig(szText,MAX_PATH),pszFileName);
	
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningCleanup"),m_ConditioningCleanup.szGetConfig(szText,MAX_PATH),pszFileName); 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningZero"),m_ConditioningZero.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningCalib"),m_ConditioningCalib.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningCalibInLine"),m_ConditioningCalibInLine.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ConditioningMeasurement"),m_ConditioningMeasurement.szGetConfig(szText,MAX_PATH),pszFileName);
	
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StateConditioning"),m_StateConditioning.szGetConfig(szText,MAX_PATH),pszFileName);
	
	/* 
	m_ElemCycleFilename.SetLabel(_T("CycleSave.ini"));
	m_ElemCycleCleanupFilename.SetLabel(_T("CycleCleanupSave.ini"));
	m_ElemCycleZeroFilename.SetLabel(_T("CycleZeroSave.ini"));
	m_ElemCycleCalibFilename.SetLabel(_T("CycleCalibSave.ini"));
	// ecriture des config
	if (bReturn) bReturn = m_ElemCycle.bWriteConfig(szGetFullPathName(m_ElemCycleFilename.szGetLabel(),szText));
	if (bReturn) bReturn = m_ElemCycleCleanup.bWriteConfig(szGetFullPathName(m_ElemCycleCleanupFilename.szGetLabel(),szText));
	if (bReturn) bReturn = m_ElemCycleZero.bWriteConfig(szGetFullPathName(m_ElemCycleZeroFilename.szGetLabel(),szText));
	if (bReturn) bReturn = m_ElemCycleCalib.bWriteConfig(szGetFullPathName(m_ElemCycleCalibFilename.szGetLabel(),szText));
	*/
	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		m_StatusFailure.bSetVal(1);
	}
	return bReturn;
}

BOOL CStream::bExecute( CElemInt8 *pCmdRun,CElemInt8 *pCmdStopEndCycle,CElemInt8 *pCmdPause
					  , CElemInt16 *pCmdJumpStep,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle
					  , CEnumInterface &EnumInterface, CElemInt8* argNumCurrentStream
					  , CElemInt8 * argpCmdCycleCalib, CElemInt8 * argpCmdCycleCalibInLine
					  , CElemInt8 * argpCmdCycleCleanup, CElemInt8 * argpCmdCycleZero
					  , CElemInt8 * pCmdRemoteControl, bool& argbNeedConditioning)
{
	BOOL bReturn = FALSE;
	int j,iOldRemoteState;
	CMesure *pMesure;
	TCHAR szTrace[500];
	
	m_CycleTimeMax.bSetVal(m_ElemCycle.m_Duration.nGetVal());
	if (m_Active.ucGetVal() != 0)
	{
		m_IsRunning.bSetVal(1);
		


		//Cycle à blanc
		if(argbNeedConditioning)
		{
			//TRACE_LOG_MSG(_T("if(argbNeedConditioning)\n"));
			for(m_ConditioningMeasurement.bSetVal(m_ConditioningCycleMeasurement.ucGetVal());
				m_ConditioningMeasurement.ucGetVal() > 0;
				m_ConditioningMeasurement.bSetVal(m_ConditioningMeasurement.ucGetVal()-1))
			{
				_stprintf(szTrace,_T("Conditionement cycle normale : %d ,cpt : %d , voie : %d \n")
							, m_ConditioningCycleMeasurement.ucGetVal()
							, m_ConditioningMeasurement.ucGetVal()
							, argNumCurrentStream->ucGetVal());
				TRACE_LOG_MSG(szTrace);
				m_StateConditioning.bSetVal(1);
				//Attente de 2 secondes pour avoir le temps de faire un dernier cycle IO avant de passer en mode SAV
				Sleep(2000);
				iOldRemoteState = pCmdRemoteControl->ucGetVal();
				pCmdRemoteControl->bSetVal(eREMOTE_SAV);
				bReturn = m_ElemCycle.bExecute(pCmdRun,pCmdStopEndCycle,pCmdPause,pCmdJumpStep,pStatusRealTime,pTimeCycle,EnumInterface, this, argNumCurrentStream);
				pCmdRemoteControl->bSetVal(iOldRemoteState);
				
			}
			m_StateConditioning.bSetVal(0);
			argbNeedConditioning = FALSE;
		}
		//TRACE_LOG_MSG(_T("Debut cycle ...  \n"));
		bReturn = m_ElemCycle.bExecute(pCmdRun,pCmdStopEndCycle,pCmdPause,pCmdJumpStep,pStatusRealTime,pTimeCycle,EnumInterface, this, argNumCurrentStream);
		m_IsRunning.bSetVal(0);
		m_CounterCycle.bIncVal(1);
		if (bReturn)
		{
			//TRACE_LOG_MSG(_T("REtour Cycle valide ...  \n"));
			// traitement des mesures
			for (j = 0; j < iGetNbrMesure();j++)
			{
				//TRACE_LOG_MSG(_T("BOUCLE FOR ...  \n"));
				pMesure = pGetAt(j);
				if (pMesure)
				{
					//Vérification des seuils de la mesure
					//TRACE_LOG_MSG(_T("DEBT traitement"));
					pMesure->bTraitement();
					//TRACE_LOG_MSG(_T("FIN traitement"));
					
				}
			}

		}

	}
	else bReturn = TRUE;

	if (!bReturn || (m_Active.ucGetVal() == 0))
	{
		if (!m_ElemCycle.m_ElemCycleStepStop.bExecute(pCmdRun,pStatusRealTime,pTimeCycle,EnumInterface))
		{
			TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: m_ElemCycleStepStop"));
			bReturn = FALSE;
		}
	}
	
	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eCycle,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		m_StatusFailure.bSetVal(1);
	}
	return bReturn;
}

BOOL CStream::bCheckAndCmdPeriodic( int& argiCheckedDays, int& argiCheckedHours
								   , CElemList* argpPeriodicHourCycle, CElemList* argpPeriodicDayCycle
								   , CElemInt8* argpPeriodicCycle, int& argiCptCycle
								   , CElemInt8 * argpCmdCycle, CElemInt8* argNumCurrentStream)
{

	SYSTEMTIME  stTime;
	GetLocalTime(&stTime);
	int iCurrentDay = stTime.wDayOfWeek;
	int iCurrentHour = stTime.wHour;
	bool bFaireHeureZeroJourSuivant = false;

	TCHAR szTrace[500];
	//TRACE_LOG_MSG(_T("Check periodique ...  \n"));

	//Periodique en nombre de cycle
	/*_stprintf(szTrace,_T("Nb cycle a faire: %d , cpt : %d , voie : %d \n")
			 ,argpPeriodicCycle->ucGetVal(), argiCptCycle, argNumCurrentStream->ucGetVal());
	TRACE_LOG_MSG(szTrace);*/
	if( (argpPeriodicCycle->ucGetVal() > 0) && (argiCptCycle++ >= argpPeriodicCycle->ucGetVal()))
	{
		
		argpCmdCycle->bSetVal(argNumCurrentStream->ucGetVal());
		argiCptCycle = 1;
	}
	else //periodique en fonction d'un jour et d'une heure 
	{
		//Si on a raté la fin du jour precedent
		if(argiCheckedDays < iCurrentDay && argiCheckedHours < 23)
		{
			iCurrentDay = argiCheckedDays;
		}
		/*_stprintf(szTrace,_T("Jour verifié/Jour a faire ? : %d/%d \n")
			 , iCurrentDay
			 , ((CElemInt8*)(argpPeriodicDayCycle->pGetAt(iCurrentDay)))->ucGetVal());
		TRACE_LOG_MSG(szTrace);*/
		//Si ce jour il faut faire un cycle periodique de calib
		if(((CElemInt8*)(argpPeriodicDayCycle->pGetAt(iCurrentDay)))->ucGetVal() != 0)
		{
			/*_stprintf(szTrace,_T("    Dernière heure verfiée/Heure courante : %d/%d \n")
							 , argiCheckedHours
							 , iCurrentHour);
			TRACE_LOG_MSG(szTrace);*/
			if(argiCheckedHours < iCurrentHour)
			{
				for(int i=argiCheckedHours; i<iCurrentHour; i++)
				{
					/*_stprintf(szTrace,_T("    Heure verfiée/Heure a faire ? : %d/%d \n")
							 , i
							 , ((CElemInt8*)(argpPeriodicHourCycle->pGetAt(i+1)))->ucGetVal());
					TRACE_LOG_MSG(szTrace);*/
					//TRACE_LOG_MSG(_T("Check des heures ...  \n"));
					if(((CElemInt8*)(argpPeriodicHourCycle->pGetAt(i+1)))->ucGetVal()!=0 )
					{
						//TRACE_LOG_MSG(_T("Envoie cmd de calib ...  \n"));
						argpCmdCycle->bSetVal(argNumCurrentStream->ucGetVal());
						i = iCurrentHour;
					}
				}
				argiCheckedHours = iCurrentHour;
			}
			//Cas du passage au jour suivant 
			else if(argiCheckedHours > iCurrentHour)
			{
				//Finir le check des heures précédente
				for(int i=argiCheckedHours; i<24; i++)
				{
					/*_stprintf(szTrace,_T("    Heure verfiée/Heure a faire ? : %d/%d \n")
							 , i
							 , ((CElemInt8*)(argpPeriodicHourCycle->pGetAt(i+1)))->ucGetVal());
					TRACE_LOG_MSG(szTrace);*/
					//TRACE_LOG_MSG(_T("Check des heures ...  \n"));
					if(((CElemInt8*)(argpPeriodicHourCycle->pGetAt(i+1)))->ucGetVal()!=0 )
					{
						//TRACE_LOG_MSG(_T("Envoie cmd de calib ...  \n"));
						argpCmdCycle->bSetVal(argNumCurrentStream->ucGetVal());
						i = iCurrentHour;
					}
				}
				argiCheckedHours = iCurrentHour;
				//Le jour courant il faut faire un cycle de maintenance
				/*_stprintf(szTrace,_T("   PinTime Heure verfiée:%d jour courant: %d pointeur existe : %s \n")
								 , argiCheckedHours
								 , iCurrentDay
								 , ((argpPeriodicDayCycle->pGetAt(iCurrentDay))? "true" : "false"));
						TRACE_LOG_MSG(szTrace);*/
				if(((CElemInt8*)(argpPeriodicDayCycle->pGetAt(iCurrentDay)))->ucGetVal() != 0)
				{
					for(int i=0; i<iCurrentHour; i++)
					{
						/*_stprintf(szTrace,_T("    Heure verfiée/Heure a faire ? : %d/%d \n")
								 , i
								 , ((CElemInt8*)(argpPeriodicHourCycle->pGetAt(i+1)))->ucGetVal());
						TRACE_LOG_MSG(szTrace);*/
						//TRACE_LOG_MSG(_T("Check des heures ...  \n"));
						if(((CElemInt8*)(argpPeriodicHourCycle->pGetAt(i+1)))->ucGetVal()!=0 )
						{
							//TRACE_LOG_MSG(_T("Envoie cmd de calib ...  \n"));
							argpCmdCycle->bSetVal(argNumCurrentStream->ucGetVal());
							i = iCurrentHour;
						}
					}
				}
			}
			//
			
		}
	}
	argiCheckedDays = stTime.wDayOfWeek;
	return TRUE;
}



/*(@!*****************************************************************************************
* Nom     : CListStream
* Role    : definition d'une liste de voie
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CElemList CListStream::m_ListMessageError(NBR_MSG_ERROR_MAX);


CListStream::CListStream():CElemBase(),CThread(),m_ListSequenceNum(NBR_SEQUENCE_CYCLE_MAX),m_ListSequenceDuree(NBR_SEQUENCE_CYCLE_MAX)
{
	m_iType = MAKE_ID(0xFF,0xFF,eTYPE_LIST_VOIE,0xEF);
	SetLabel(_T("CListStream"));
	m_CmdLoadNumConfig.SetLabel(_T("m_CmdLoadNumConfig"));;
	m_CmdLoadNumConfig.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_LOAD_NUM_CONFIG));

	m_CmdSaveNumConfig.SetLabel(_T("m_CmdSaveNumConfig"));;
	m_CmdSaveNumConfig.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_SAVE_NUM_CONFIG));

	m_CmdRun.SetLabel(_T("m_CmdRun"));;
	m_CmdRun.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_RUN));

	m_CmdPause.SetLabel(_T("m_CmdPause"));;
	m_CmdPause.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_PAUSE));

	m_CmdCycleCalib.SetLabel(_T("m_CmdCycleCalib"));;
	m_CmdCycleCalib.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_CYCLE_CALIB));

	m_CmdCycleCalibInLine.SetLabel(_T("m_CmdCycleCalibInLine"));;
	m_CmdCycleCalibInLine.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_CYCLE_CALIB_IN_LINE));

	m_CmdCycleZero.SetLabel(_T("m_CmdCycleZero"));;
	m_CmdCycleZero.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_CYCLE_ZERO));

	m_CmdCycleCleanup.SetLabel(_T("m_CmdCycleCleanup"));;
	m_CmdCycleCleanup.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_CYCLE_CLEANUP));

	m_CmdJumpStep.SetLabel(_T("m_CmdJumpStep"));;
	m_CmdJumpStep.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT16,eID_LISTSTREAM_CMD_JUMP_STEP));

	m_CmdRemoteControl.SetLabel(_T("m_CmdRemoteControl"));;
	m_CmdRemoteControl.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_REMOTE_CONTROL));

	m_CmdStopEndCycle.SetLabel(_T("m_CmdStopEndCycle"));;
	m_CmdStopEndCycle.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_STOP_END_CYCLE));

	m_CmdMaintenanceManuel.SetLabel(_T("m_CmdMaintenanceManuel"));;
	m_CmdMaintenanceManuel.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_MAINTENANCE));

	m_NumCurrentStream.SetLabel(_T("m_NumCurrentStream"));;
	m_NumCurrentStream.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_NUM_CURRENT_STREAM));

	m_NumCurrentConfig.SetLabel(_T("m_NumCurrentConfig"));
	m_NumCurrentConfig.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_NUM_CURRENT_CONFIG));

	m_NumVersion.SetLabel(_T("m_NumVersion"));
	m_NumVersion.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_NUM_VERSION));

	m_bStateMaintenance.SetLabel(_T("m_bStateMaintenance"));;
	m_bStateMaintenance.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_MAINTENANCE));

	m_bStateCalib.SetLabel(_T("m_bStateCalib"));;
	m_bStateCalib.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_CALIB));

	m_bStateCalibInLine.SetLabel(_T("m_bStateCalibInLine"));;
	m_bStateCalibInLine.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_CALIB_IN_LINE));

	m_bStateZero.SetLabel(_T("m_bStateZero"));;
	m_bStateZero.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_ZERO));

	m_bStateCleanup.SetLabel(_T("m_bStateCleanup"));;
	m_bStateCleanup.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_CLEANUP));

	m_bStatusFailure.SetLabel(_T("m_bStatusFailure"));;
	m_bStatusFailure.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATUS_FAILURE));

	m_bStatusSupervision.SetLabel(_T("m_bStatusSupervision"));;
	m_bStatusSupervision.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATUS_SUPPERVISION));

	m_CurrentTimeCycle.SetLabel(_T("m_CurrentTimeCycle"));;
	m_CurrentTimeCycle.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT16,eID_LISTSTREAM_CURRENT_TIME_CYCLE));

	m_TimeRemaingUntilNextCycle.SetLabel(_T("m_TimeRemaingUntilNextCycle"));;
	m_TimeRemaingUntilNextCycle.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT16,eID_LISTSTREAM_TIMER));

	m_bStatusRealTime.SetLabel(_T("m_bStatusRealTime"));;
	m_bStatusRealTime.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT16,eID_LISTSTREAM_STATUS_REALTIME));

	m_ListSequenceNum.SetLabel(_T("m_ListSequenceNum"));;
	m_ListSequenceNum.SetType(MAKE_ID(0xFF,0xFF,eTYPE_LIST,eID_LISTSTREAM_LIST_SEQUENCE_NUM));

	m_ListSequenceDuree.SetLabel(_T("m_ListSequenceDuree"));;
	m_ListSequenceDuree.SetType(MAKE_ID(0xFF,0xFF,eTYPE_LIST,eID_LISTSTREAM_LIST_SEQUENCE_DUREE));

	m_ListMessageError.SetLabel(_T("m_ListMessageError"));;
	m_ListMessageError.SetType(MAKE_ID(0xFF,0xFF,eTYPE_LIST,eID_LISTSTREAM_LIST_MESSAGE_ERROR));

	// m_CellTemperatureOrder 
	m_CellTemperatureOrder.SetLabel(_T("m_CellTemperatureOrder"));;
	m_CellTemperatureOrder.SetType(MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,eID_LISTSTREAM_CELL_TEMPERATURE_ORDER));
	// m_CellTemperatureOffset
	m_CellTemperatureOffset.SetLabel(_T("m_CellTemperatureOffset"));;
	m_CellTemperatureOffset.SetType(MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,eID_LISTSTREAM_CELL_OFFSET));
	//m_Average
	m_Average.SetLabel(_T("m_Average"));;
	m_Average.SetType(MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_AVERAGE));
	
	m_GainProbe.SetLabel(_T("m_GainProbe"));;
	m_GainProbe.SetType(MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,eID_LISTSTREAM_PROBE_GAIN));

	m_OffsetProbe.SetLabel(_T("m_OffsetProbe"));;
	m_OffsetProbe.SetType(MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,eID_LISTSTREAM_PROBE_OFFSET));

	m_iNbrStream = 0;
	memset(&m_apStream[0],0,sizeof(m_apStream));
	m_bNeedConditioning = FALSE;
}

CListStream::~CListStream()
{
	m_ListSequenceNum.RemoveAll();
	m_ListSequenceDuree.RemoveAll();
	m_ListMessageError.RemoveAll();
	RemoveAll();
}


void CListStream::RemoveAll()
{
	while (m_iNbrStream > 0)
	{
		m_iNbrStream--;
		if (m_apStream[m_iNbrStream]) 
		{
			delete(m_apStream[m_iNbrStream]);
			m_apStream[m_iNbrStream] = NULL;
		}
	}
	m_iNbrStream = 0;
}

CStream *CListStream::pNew()
{
	CStream *pStream = NULL;

	if (m_iNbrStream < NBR_STREAM_MAX)
	{
		pStream = new CStream((BYTE)m_iNbrStream);
		if (pStream)
		{
			m_apStream[m_iNbrStream] = pStream;
			m_iNbrStream++;
		}
	}
	return pStream;
}

CStream *CListStream::pGetAt(int iPos)
{
	CStream *pStream = NULL;

	if ((iPos < m_iNbrStream) && (iPos > -1))
	{
		pStream = m_apStream[iPos];
	}
	return pStream;
}

BOOL CListStream::bSerialize(CContext &Context)
{
	int i;
	BOOL bReturn = TRUE;

	bReturn = CElemBase::bSerialize(Context);
	if (bReturn) bReturn = m_CmdLoadNumConfig.bSerialize(Context);
	if (bReturn) bReturn = m_CmdSaveNumConfig.bSerialize(Context);
	if (bReturn) bReturn = m_CmdRun.bSerialize(Context);
	if (bReturn) bReturn = m_CmdPause.bSerialize(Context);
	if (bReturn) bReturn = m_CmdCycleCalib.bSerialize(Context);
	if (bReturn) bReturn = m_CmdCycleCalibInLine.bSerialize(Context);
	if (bReturn) bReturn = m_CmdCycleZero.bSerialize(Context);
	if (bReturn) bReturn = m_CmdCycleCleanup.bSerialize(Context);
	if (bReturn) bReturn = m_CmdJumpStep.bSerialize(Context);
	if (bReturn) bReturn = m_CmdRemoteControl.bSerialize(Context);
	if (bReturn) bReturn = m_CmdStopEndCycle.bSerialize(Context);
	if (bReturn) bReturn = m_CmdMaintenanceManuel.bSerialize(Context);
	if (bReturn) bReturn = m_NumCurrentStream.bSerialize(Context);
	if (bReturn) bReturn = m_NumCurrentConfig.bSerialize(Context);
	if (bReturn) bReturn = m_NumVersion.bSerialize(Context);
	if (bReturn) bReturn = m_bStateMaintenance.bSerialize(Context);
	if (bReturn) bReturn = m_bStateCalib.bSerialize(Context);
	if (bReturn) bReturn = m_bStateCalibInLine.bSerialize(Context);
	if (bReturn) bReturn = m_bStateZero.bSerialize(Context);
	if (bReturn) bReturn = m_bStateCleanup.bSerialize(Context);
	if (bReturn) bReturn = m_bStatusFailure.bSerialize(Context);
	if (bReturn) bReturn = m_bStatusSupervision.bSerialize(Context);
	if (bReturn) bReturn = m_CurrentTimeCycle.bSerialize(Context);
	if (bReturn) bReturn = m_TimeRemaingUntilNextCycle.bSerialize(Context);
	if (bReturn) bReturn = m_bStatusRealTime.bSerialize(Context);
	if (bReturn) bReturn = m_CellTemperatureOrder.bSerialize(Context); 
	if (bReturn) bReturn = m_CellTemperatureOffset.bSerialize(Context);
	if (bReturn) bReturn = m_Average.bSerialize(Context);
	if (bReturn) bReturn = m_GainProbe.bSerialize(Context);
	if (bReturn) bReturn = m_OffsetProbe.bSerialize(Context);

	if (bReturn) bReturn = m_ListSequenceNum.bSerialize(Context);
	if (bReturn) bReturn = m_ListSequenceDuree.bSerialize(Context);
	if (bReturn) bReturn = m_ListMessageError.bSerialize(Context);

	if (bReturn) bReturn = bLoadSaveInt32(m_iNbrStream,Context);

	for (i = 0;(bReturn) && (i < m_iNbrStream);i++)
	{
		if (!Context.m_bSave) m_apStream[i] = new CStream(i);
		if (m_apStream[i]) bReturn = m_apStream[i]->bSerialize(Context);
	}

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}

int CListStream::iGetStreamSize(CContext &Context)
{
	int i;
	int iSize = 0;

	iSize = CElemBase::iGetStreamSize(Context);
	iSize += m_CmdLoadNumConfig.iGetStreamSize(Context);
	iSize += m_CmdSaveNumConfig.iGetStreamSize(Context);
	iSize += m_CmdRun.iGetStreamSize(Context);
	iSize += m_CmdPause.iGetStreamSize(Context);
	iSize += m_CmdCycleCalib.iGetStreamSize(Context);
	iSize += m_CmdCycleCalibInLine.iGetStreamSize(Context);
	iSize += m_CmdCycleZero.iGetStreamSize(Context);
	iSize += m_CmdCycleCleanup.iGetStreamSize(Context);
	iSize += m_CmdJumpStep.iGetStreamSize(Context);
	iSize += m_CmdRemoteControl.iGetStreamSize(Context);
	iSize += m_CmdStopEndCycle.iGetStreamSize(Context);
	iSize += m_CmdMaintenanceManuel.iGetStreamSize(Context);
	iSize += m_NumCurrentStream.iGetStreamSize(Context);
	iSize += m_NumCurrentConfig.iGetStreamSize(Context);
	iSize += m_NumVersion.iGetStreamSize(Context);
	iSize += m_bStateMaintenance.iGetStreamSize(Context);
	iSize += m_bStateCalib.iGetStreamSize(Context);
	iSize += m_bStateCalibInLine.iGetStreamSize(Context);
	iSize += m_bStateZero.iGetStreamSize(Context);
	iSize += m_bStateCleanup.iGetStreamSize(Context);
	iSize += m_bStatusFailure.iGetStreamSize(Context);
	iSize += m_bStatusSupervision.iGetStreamSize(Context);
	iSize += m_CurrentTimeCycle.iGetStreamSize(Context);
	iSize += m_TimeRemaingUntilNextCycle.iGetStreamSize(Context);
	iSize += m_bStatusRealTime.iGetStreamSize(Context);
	iSize += m_CellTemperatureOrder.iGetStreamSize(Context);
	iSize += m_CellTemperatureOffset.iGetStreamSize(Context);
	iSize += m_Average.iGetStreamSize(Context);
	iSize += m_GainProbe.iGetStreamSize(Context);
	iSize += m_OffsetProbe.iGetStreamSize(Context);

	iSize += m_ListSequenceNum.iGetStreamSize(Context);
	iSize += m_ListSequenceDuree.iGetStreamSize(Context);
	iSize += m_ListMessageError.iGetStreamSize(Context);


	iSize += sizeof(m_iNbrStream);
	for (i = 0;i < m_iNbrStream;i++)
	{
		if (m_apStream[i]) iSize += m_apStream[i]->iGetStreamSize(Context);
	}
	return iSize;
}
CElemBase *CListStream::pFindOrCreateElemFromID(long lID)
{
	CElemBase *pElem = NULL;

	pElem = pFindElemFromID(lID);
	if (pElem == NULL)
	{
		if (NUM_TYPE(lID) == eTYPE_TXT) pElem = new CElemBase();
		else if (NUM_TYPE(lID) == eTYPE_BITFIELD8) pElem = new CElemFieldBit8();
		else if (NUM_TYPE(lID) == eTYPE_BITFIELD16) pElem = new CElemFieldBit16();
		else if (NUM_TYPE(lID) == eTYPE_INT8) pElem = new CElemInt8();
		else if (NUM_TYPE(lID) == eTYPE_INT16) pElem = new CElemInt16();
		else if (NUM_TYPE(lID) == eTYPE_INT32) pElem = new CElemInt32();
		else if (NUM_TYPE(lID) == eTYPE_FLOAT) pElem = new CElemFloat();
		else pElem = new CElemFieldBit8();
		pElem->SetType(lID);
		pElem->SetAutoDelete(TRUE);
	}
	return pElem;
}

CElemBase *CListStream::pFindElemFromID(long lID)
{
	CStream *pStream = NULL;
	CMesure *pMesure = NULL;
	CElemBase *pElem = NULL;

	pStream = pGetAt(NUM_VOIE(lID));
	if (pStream)
	{
		pMesure = pStream->pGetAt(NUM_MESURE(lID));
		if (pMesure)
		{
			if (pMesure->iGetType() == lID) pElem = pMesure;
			else if (pMesure->m_Val.iGetType() == lID) pElem = &pMesure->m_Val;
			else if (pMesure->m_ValMax.iGetType() == lID) pElem = &pMesure->m_ValMax;
			else if (pMesure->m_ValMin.iGetType() == lID) pElem = &pMesure->m_ValMin;
			else if (pMesure->m_StatusFailure.iGetType() == lID) pElem = &pMesure->m_StatusFailure;
			else if (pMesure->m_Threshold1.iGetType() == lID) pElem = &pMesure->m_Threshold1;
			else if (pMesure->m_Threshold2.iGetType() == lID) pElem = &pMesure->m_Threshold2;
			else if (pMesure->m_StatusThreshold1.iGetType() == lID) pElem = &pMesure->m_StatusThreshold1;
			else if (pMesure->m_StatusThreshold2.iGetType() == lID) pElem = &pMesure->m_StatusThreshold2;
			else if (pMesure->m_AnalogZero.iGetType() == lID) pElem = &pMesure->m_AnalogZero;
			else if (pMesure->m_AnalogPlage.iGetType() == lID) pElem = &pMesure->m_AnalogPlage;
			else if (pMesure->m_CalibCoeff.iGetType() == lID) pElem = &pMesure->m_CalibCoeff;
			else if (pMesure->m_CalibZeroWater.iGetType() == lID) pElem = &pMesure->m_CalibZeroWater;
			else if (pMesure->m_CalibZeroAir.iGetType() == lID) pElem = &pMesure->m_CalibZeroAir;
			else if (pMesure->m_CalibStatusCoeff.iGetType() == lID) pElem = &pMesure->m_CalibStatusCoeff;
			else if (pMesure->m_CalibStatusZero.iGetType() == lID) pElem = &pMesure->m_CalibStatusZero;
			else if (pMesure->m_SettingThreshold.iGetType() == lID) pElem = &pMesure->m_SettingThreshold;
			else if (pMesure->m_ValJbusSlave.iGetType() == lID) pElem = &pMesure->m_ValJbusSlave;
			else if (pMesure->m_CoeffValJbusSlave.iGetType() == lID) pElem = &pMesure->m_CoeffValJbusSlave;
			else if (pMesure->m_ValAna.iGetType() == lID) pElem = &pMesure->m_ValAna;
			else if (pMesure->m_ValMaxConvertisseur.iGetType() == lID) pElem = &pMesure->m_ValMaxConvertisseur;
			else if (pMesure->m_ValMinConvertisseur.iGetType() == lID) pElem = &pMesure->m_ValMinConvertisseur;
			else if (pMesure->m_ListCoeffLinear.iGetType() == lID) pElem = &pMesure->m_ListCoeffLinear;
			else if (pMesure->m_ListMesureMoy.iGetType() == lID) pElem = &pMesure->m_ListMesureMoy;
			else if (pMesure->m_ListRealtimeData.iGetType() == lID) pElem = &pMesure->m_ListRealtimeData;
			else if (pMesure->m_OpticalGain.iGetType() == lID) pElem = &pMesure->m_OpticalGain;
			else if (pMesure->m_ZeroOpticalMeasurement.iGetType() == lID) pElem = &pMesure->m_ZeroOpticalMeasurement;
			else if (pMesure->m_AbsorbanceValue.iGetType() == lID) pElem = &pMesure->m_AbsorbanceValue;
			else if (pMesure->m_StandardValueBefore.iGetType() == lID) pElem = &pMesure->m_StandardValueBefore;
			else if (pMesure->m_StandardValueAfter.iGetType() == lID) pElem = &pMesure->m_StandardValueAfter;
			else if (pMesure->m_CalibCoeffNew.iGetType() == lID) pElem = &pMesure->m_CalibCoeffNew;
			else if (pMesure->m_OpticalMeasurement.iGetType() == lID) pElem = &pMesure->m_OpticalMeasurement;
			else if (pMesure->m_AbsorbanceReference.iGetType() == lID) pElem = &pMesure->m_AbsorbanceReference;
			else if (pMesure->m_RawConcentration.iGetType() == lID) pElem = &pMesure->m_RawConcentration; 
			
			else if (pMesure->m_CorrectedAbsorbance.iGetType() == lID) pElem = &pMesure->m_CorrectedAbsorbance;
			else if (pMesure->m_RealAbsorbance.iGetType() == lID) pElem = &pMesure->m_RealAbsorbance;
			else if (pMesure->m_Delta.iGetType() == lID) pElem = &pMesure->m_Delta;
			else if (pMesure->m_CalibZeroWaterNew.iGetType() == lID) pElem = &pMesure->m_CalibZeroWaterNew;
			else if (pMesure->m_NumProgram.iGetType() == lID) pElem = &pMesure->m_NumProgram;					
			else if (pMesure->m_AirSetPointAdjustement.iGetType() == lID)pElem = &pMesure->m_AirSetPointAdjustement;
			else if (pMesure->m_AirRefMeasureRedrSync.iGetType() == lID) pElem = &pMesure->m_AirRefMeasureRedrSync;
			else if (pMesure->m_AirWaterFlag.iGetType() == lID) pElem = &pMesure->m_AirWaterFlag;
			else if (pMesure->m_RefBaseline.iGetType() == lID) pElem = &pMesure->m_RefBaseline;
			else if (pMesure->m_Water90.iGetType() == lID) pElem = &pMesure->m_Water90;
			else if (pMesure->m_Turbidity90.iGetType() == lID) pElem = &pMesure->m_Turbidity90;
			else if (pMesure->m_TurbidityFinal.iGetType() == lID) pElem = &pMesure->m_TurbidityFinal;
			else if (pMesure->m_TurbidityCoef.iGetType() == lID) pElem = &pMesure->m_TurbidityCoef;
			else if (pMesure->m_TurbidityStandard.iGetType() == lID) pElem = &pMesure->m_TurbidityStandard;
			else if (pMesure->m_AirOpticalGain.iGetType() == lID) pElem = &pMesure->m_AirOpticalGain;
			else if (pMesure->m_AirRedrSync.iGetType() == lID) pElem = &pMesure->m_AirRedrSync;
			else if (pMesure->m_AbsorbanceTurbidity180.iGetType() == lID) pElem = &pMesure->m_AbsorbanceTurbidity180;
			else if (pMesure->m_AbsorbanceCorrected.iGetType() == lID) pElem = &pMesure->m_AbsorbanceCorrected;
			else if (pMesure->m_OpticalGain90.iGetType() == lID) pElem = &pMesure->m_OpticalGain90;
			else if (pMesure->m_CourantLedColo.iGetType() == lID) pElem = &pMesure->m_CourantLedColo;
			else if (pMesure->m_MeasureSetByLed.iGetType() == lID) pElem = &pMesure->m_MeasureSetByLed;
			else if (pMesure->m_Turbidity.iGetType() == lID) pElem = &pMesure->m_Turbidity;
			else if (pMesure->m_Temperature.iGetType() == lID) pElem = &pMesure->m_Temperature;
			else if (pMesure->m_ZeroStandard.iGetType() == lID) pElem = &pMesure->m_ZeroStandard;
			else if (pMesure->m_CoefDilution.iGetType() == lID) pElem = &pMesure->m_CoefDilution;
			else if (pMesure->m_CoefAjustement.iGetType() == lID) pElem = &pMesure->m_CoefAjustement;

			else if (pMesure->m_StatusSonde.iGetType() == lID) pElem = &pMesure->m_StatusSonde;
			else if (pMesure->m_StatusConcentration.iGetType() == lID) pElem = &pMesure->m_StatusConcentration;
			else if (pMesure->m_AlarmDelta.iGetType() == lID) pElem = &pMesure->m_AlarmDelta;
		}
		else 
		{
			if (pStream->iGetType() == lID) pElem = pStream;
			else if (pStream->m_CycleTimeMax.iGetType() == lID) pElem = &pStream->m_CycleTimeMax;
			else if (pStream->m_StreamName.iGetType() == lID) pElem = &pStream->m_StreamName;
			else if (pStream->m_CycleTimeCurrent.iGetType() == lID) pElem = &pStream->m_CycleTimeCurrent;
			else if (pStream->m_Active.iGetType() == lID) pElem = &pStream->m_Active;
			else if (pStream->m_StatusFailure.iGetType() == lID) pElem = &pStream->m_StatusFailure;
			else if (pStream->m_StatusWaterFailure.iGetType() == lID) pElem = &pStream->m_StatusWaterFailure;
			else if (pStream->m_IsRunning.iGetType() == lID) pElem = &pStream->m_IsRunning;
			else if (pStream->m_CounterCycle.iGetType() == lID) pElem = &pStream->m_CounterCycle;
			else if (pStream->m_CellTemperature.iGetType() == lID) pElem = &pStream->m_CellTemperature;
			else if (pStream->m_WaterFailureSetPoint.iGetType() == lID) pElem = &pStream->m_WaterFailureSetPoint;
			else if (pStream->m_OpticalSetPoint.iGetType() == lID) pElem = &pStream->m_OpticalSetPoint;
			else if (pStream->m_CellTemperatureSetPoint.iGetType() == lID) pElem = &pStream->m_CellTemperatureSetPoint;
			else if (pStream->m_PressureMeasurement.iGetType() == lID) pElem = &pStream->m_PressureMeasurement;
			else if (pStream->m_ThresholdTemperatureProbe.iGetType() == lID) pElem = &pStream->m_ThresholdTemperatureProbe; 
			else if (pStream->m_TemperatureProbe.iGetType() == lID) pElem = &pStream->m_TemperatureProbe;
			else if (pStream->m_SettingColorThreshold1.iGetType() == lID) pElem = &pStream->m_SettingColorThreshold1;
			else if (pStream->m_SettingColorThreshold2.iGetType() == lID) pElem = &pStream->m_SettingColorThreshold2;  
			else if (pStream->m_PeriodicCycleCleanup.iGetType() == lID) pElem = &pStream->m_PeriodicCycleCleanup; 
			else if (pStream->m_PeriodicCycleZero.iGetType() == lID) pElem = &pStream->m_PeriodicCycleZero;
			else if (pStream->m_PeriodicCycleCalib.iGetType() == lID) pElem = &pStream->m_PeriodicCycleCalib;
			else if (pStream->m_PeriodicCycleCalibInLine.iGetType() == lID) pElem = &pStream->m_PeriodicCycleCalibInLine;
			else if (pStream->m_ListPeriodicHourCycleCleanup.iGetType() == lID) pElem = &pStream->m_ListPeriodicHourCycleCleanup; 
			else if (pStream->m_ListPeriodicHourCycleZero.iGetType() == lID) pElem = &pStream->m_ListPeriodicHourCycleZero;
			else if (pStream->m_ListPeriodicHourCycleCalib.iGetType() == lID) pElem = &pStream->m_ListPeriodicHourCycleCalib;
			else if (pStream->m_ListPeriodicHourCycleCalibInLine.iGetType() == lID) pElem = &pStream->m_ListPeriodicHourCycleCalibInLine;
			else if (pStream->m_ListPeriodicDayCycleCleanup.iGetType() == lID) pElem = &pStream->m_ListPeriodicDayCycleCleanup; 
			else if (pStream->m_ListPeriodicDayCycleZero.iGetType() == lID) pElem = &pStream->m_ListPeriodicDayCycleZero;
			else if (pStream->m_ListPeriodicDayCycleCalib.iGetType() == lID) pElem = &pStream->m_ListPeriodicDayCycleCalib;
			else if (pStream->m_ListPeriodicDayCycleCalibInLine.iGetType() == lID) pElem = &pStream->m_ListPeriodicDayCycleCalibInLine;
			else if (pStream->m_ConditioningCycleCleanup.iGetType() == lID) pElem = &pStream->m_ConditioningCycleCleanup; 
			else if (pStream->m_ConditioningCycleZero.iGetType() == lID) pElem = &pStream->m_ConditioningCycleZero;
			else if (pStream->m_ConditioningCycleCalib.iGetType() == lID) pElem = &pStream->m_ConditioningCycleCalib;
			else if (pStream->m_ConditioningCycleCalibInLine.iGetType() == lID) pElem = &pStream->m_ConditioningCycleCalibInLine;
			else if (pStream->m_ConditioningCycleMeasurement.iGetType() == lID) pElem = &pStream->m_ConditioningCycleMeasurement;
			else if (pStream->m_ConditioningCleanup.iGetType() == lID) pElem = &pStream->m_ConditioningCleanup; 
			else if (pStream->m_ConditioningZero.iGetType() == lID) pElem = &pStream->m_ConditioningZero;
			else if (pStream->m_ConditioningCalib.iGetType() == lID) pElem = &pStream->m_ConditioningCalib;
			else if (pStream->m_ConditioningCalibInLine.iGetType() == lID) pElem = &pStream->m_ConditioningCalibInLine;
			else if (pStream->m_ConditioningMeasurement.iGetType() == lID) pElem = &pStream->m_ConditioningMeasurement;
			else if (pStream->m_StateConditioning.iGetType() == lID) pElem = &pStream->m_StateConditioning;
		
		}
	}
	else
	{
		if (iGetType() == lID) pElem = this;
		else if (m_CmdLoadNumConfig.iGetType() == lID) pElem = &m_CmdLoadNumConfig;
		else if (m_CmdSaveNumConfig.iGetType() == lID) pElem = &m_CmdSaveNumConfig;
		else if (m_CmdRun.iGetType() == lID) pElem = &m_CmdRun;
		else if (m_CmdPause.iGetType() == lID) pElem = &m_CmdPause;
		else if (m_CmdCycleCalib.iGetType() == lID) pElem = &m_CmdCycleCalib;
		else if (m_CmdCycleCalibInLine.iGetType() == lID) pElem = &m_CmdCycleCalibInLine;
		else if (m_CmdCycleZero.iGetType() == lID) pElem = &m_CmdCycleZero;
		else if (m_CmdCycleCleanup.iGetType() == lID) pElem = &m_CmdCycleCleanup;
		else if (m_CmdJumpStep.iGetType() == lID) pElem = &m_CmdJumpStep;
		else if (m_CmdRemoteControl.iGetType() == lID) pElem = &m_CmdRemoteControl;
		else if (m_CmdStopEndCycle.iGetType() == lID) pElem = &m_CmdStopEndCycle;
		else if (m_CmdMaintenanceManuel.iGetType() == lID) pElem = &m_CmdMaintenanceManuel;
		else if (m_NumCurrentStream.iGetType() == lID) pElem = &m_NumCurrentStream;
		else if (m_NumCurrentConfig.iGetType() == lID) pElem = &m_NumCurrentConfig;
		else if (m_NumVersion.iGetType() == lID) pElem = &m_NumVersion;
		else if (m_bStateMaintenance.iGetType() == lID) pElem = &m_bStateMaintenance;
		else if (m_bStateCalib.iGetType() == lID) pElem = &m_bStateCalib;
		else if (m_bStateCalibInLine.iGetType() == lID) pElem = &m_bStateCalibInLine;
		else if (m_bStateZero.iGetType() == lID) pElem = &m_bStateZero;
		else if (m_bStateCleanup.iGetType() == lID) pElem = &m_bStateCleanup;
		else if (m_bStatusFailure.iGetType() == lID) pElem = &m_bStatusFailure;
		else if (m_bStatusSupervision.iGetType() == lID) pElem = &m_bStatusSupervision;
		else if (m_CurrentTimeCycle.iGetType() == lID) pElem = &m_CurrentTimeCycle;
		else if (m_TimeRemaingUntilNextCycle.iGetType() == lID) pElem = &m_TimeRemaingUntilNextCycle;
		else if (m_bStatusRealTime.iGetType() == lID) pElem = &m_bStatusRealTime;
		else if (m_CellTemperatureOrder.iGetType() == lID) pElem = &m_CellTemperatureOrder;
		else if (m_CellTemperatureOffset.iGetType() == lID) pElem = &m_CellTemperatureOffset;
		else if (m_Average.iGetType() == lID) pElem = &m_Average;
		else if (m_GainProbe.iGetType() == lID) pElem = &m_GainProbe;
		else if (m_OffsetProbe.iGetType() == lID) pElem = &m_OffsetProbe;
		
		else if (m_ListSequenceNum.iGetType() == lID) pElem = &m_ListSequenceNum;
		else if (m_ListSequenceDuree.iGetType() == lID) pElem = &m_ListSequenceDuree;
		else if (m_ListMessageError.iGetType() == lID) pElem = &m_ListMessageError;

		else if (CElemCycle::m_CurrentStep.iGetType() == lID) 
		{
			pElem = &CElemCycle::m_CurrentStep;
		}
	}

	return pElem;
}


BOOL CListStream::bSerialize(BOOL bSave, LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;
	CContext Context(bSave,NULL,NULL,0,FALSE/*mode flottant*/,TRUE);

	if (bSave) Context.m_hFile = _tfopen(pszFileName,_T("wb"));
	else Context.m_hFile = _tfopen(pszFileName,_T("rb"));
	if (Context.m_hFile)
	{
		bReturn = bSerialize(Context);
		fclose(Context.m_hFile);
	}

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		m_bStatusFailure.bSetVal(1);
	}
	return bReturn;
}

//Lit la configuration temporaire sauvegardé par l'IHM
//Entrée : Nom du fichier contenant la config
BOOL CListStream::bReadTempConfig(LPCTSTR pszFileName)
{
	TCHAR szLine[MAX_PATH];
	long nPositionInFile=0;
	long lId;
	TCHAR *pcId;
	CElemBase* pElem;

	//Tant qu'on a des lignes à lire dans le fichier
	while(bReadLineFromPos(pszFileName,szLine,nPositionInFile))
	{
		lstrcpy(pcId,szLine);
		// Récupération de l'id à partir de la ligne (1er champ)
		pcId = _tcstok( pcId, _T("|") ); 
		
		//Convertion de l'Id
		_stscanf(pcId,_T("%x"),&lId);
		pElem = pFindOrCreateElemFromID(lId);
		pElem->bSetConfig(szLine);

	}
	return TRUE;
}
BOOL CListStream::bReadConfig(LPCTSTR pszFileName)
{
	BOOL bReturn = TRUE;
	int i;
	int iNbrVoie;
	TCHAR szText[MAX_PATH];
	TCHAR szText2[MAX_PATH];
	TCHAR szFailureField[MAX_PATH];
	CStream *pStream;
	CElemBase *pElem;


	// parametres de DEBUG et TRACE
	dwGetPrivateProfileString(_T("Divers"),_T("_szLogFileDir"),_T("\\"),_szLogFileDir,sizeof(_szLogFileDir)/sizeof(TCHAR),pszFileName);
	dwGetPrivateProfileString(_T("Divers"),_T("_szLogErrorPrgFileDir"),_T("\\"),_szLogErrorPrgFileDir,sizeof(_szLogErrorPrgFileDir)/sizeof(TCHAR),pszFileName);
	dwGetPrivateProfileString(_T("Divers"),_T("_szUserLogFileDir"),_T("\\"),_szUserLogFileDir,sizeof(_szUserLogFileDir)/sizeof(TCHAR),pszFileName);
	_bTraceScreen = iGetPrivateProfileInt(_T("TRACE_DEBUG"),_T("_bTraceScreen"),0,pszFileName);
	_bDebugView = iGetPrivateProfileInt(_T("TRACE_DEBUG"),_T("_bDebugView"),0,pszFileName);
	_bLogFile = iGetPrivateProfileInt(_T("TRACE_DEBUG"),_T("_bLogFile"),0,pszFileName);
	_bErrFile = iGetPrivateProfileInt(_T("TRACE_DEBUG"),_T("_bErrFile"),1,pszFileName);

	_bShowError = iGetPrivateProfileInt(_T("TRACE_DEBUG"),_T("_bShowError"),0,pszFileName);  
	_bShowWarning = iGetPrivateProfileInt(_T("TRACE_DEBUG"),_T("_bShowWarning"),0,pszFileName);
	_bShowInformation = iGetPrivateProfileInt(_T("TRACE_DEBUG"),_T("_bShowInformation"),0,pszFileName);
	_bShowDebug = iGetPrivateProfileInt(_T("TRACE_DEBUG"),_T("_bShowDebug"),0,pszFileName);


	// utile pour info sur pas en cours
	_stprintf(szText2,_T("0x%x|En Attente"),MAKE_ID(0xFF,0xFF,eTYPE_CYCLE_STEP,eID_STREAM_CURRENT_STEP));
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CurrentStep"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	bReturn = CElemCycle::m_CurrentStep.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CurrentStep"));
	// cmd m_CmdSaveNumConfig
	_stprintf(szText2,_T("0x%x|CmdSaveNumConfig|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_SAVE_NUM_CONFIG),m_CmdSaveNumConfig.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdSaveNumConfig"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn)bReturn = m_CmdSaveNumConfig.bSetConfig(szText);
	// cmd m_CmdLoadNumConfig
	_stprintf(szText2,_T("0x%x|CmdLoadNumConfig|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_LOAD_NUM_CONFIG),m_CmdLoadNumConfig.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdLoadNumConfig"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdLoadNumConfig.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdLoadNumConfig"));
	
	// cmd run/stop
	_stprintf(szText2,_T("0x%x|CmdRun|1|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_RUN),m_CmdRun.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdRun"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdRun.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdRun"));
	// cmd pause
	_stprintf(szText2,_T("0x%x|CmdPause|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_PAUSE),m_CmdPause.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdPause"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdPause.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdPause"));
	// cmd cycle calib
	_stprintf(szText2,_T("0x%x|CmdCycleCalib|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_CYCLE_CALIB),m_CmdCycleCalib.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdCycleCalib"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdCycleCalib.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdCycleCalib"));
	// cmd cycle CalibInLine
	_stprintf(szText2,_T("0x%x|m_CmdCycleCalibInLine|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_CYCLE_CALIB_IN_LINE),m_CmdCycleCalibInLine.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdCycleCalibInLine"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdCycleCalibInLine.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdCycleCalibInLine"));
	// cmd cycle zero 
	_stprintf(szText2,_T("0x%x|CmdCycleZero|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_CYCLE_ZERO),m_CmdCycleZero.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdCycleZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdCycleZero.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdCycleZero"));
	// cmd cleanup
	_stprintf(szText2,_T("0x%x|CmdCycleCleanup|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_CYCLE_CLEANUP),m_CmdCycleCleanup.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdCycleCleanup"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdCycleCleanup.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdCycleCleanup"));
	// cmd jump step
	_stprintf(szText2,_T("0x%x|CmdJumpStep|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT16,eID_LISTSTREAM_CMD_JUMP_STEP),m_CmdJumpStep.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdJumpStep"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdJumpStep.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdJumpStep"));
	// cmd remote Control
	_stprintf(szText2,_T("0x%x|CmdRemoteControl|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_REMOTE_CONTROL),m_CmdRemoteControl.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdRemoteControl"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdRemoteControl.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdRemoteControl"));
	SetRemoteControl();
	// cmd stop fin de cycle
	_stprintf(szText2,_T("0x%x|m_CmdStopEndCycle|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_STOP_END_CYCLE),m_CmdStopEndCycle.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdStopEndCycle"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdStopEndCycle.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdStopEndCycle"));

	// m_CmdMaintenanceManuel
	_stprintf(szText2,_T("0x%x|m_CmdMaintenanceManuel|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_MAINTENANCE),m_CmdMaintenanceManuel.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CmdMaintenanceManuel"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CmdMaintenanceManuel.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CmdMaintenanceManuel"));

	// num voie courante
	_stprintf(szText2,_T("0x%x|NumCurrentStream|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_NUM_CURRENT_STREAM),m_NumCurrentStream.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_NumCurrentStream"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_NumCurrentStream.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_NumCurrentStream"));
	// num config courante
	_stprintf(szText2,_T("0x%x|NumCurrentConfig|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_NUM_CURRENT_CONFIG),m_NumCurrentConfig.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_NumCurrentConfig"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_NumCurrentConfig.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_NumCurrentConfig"));
	// num version
	_stprintf(szText2,_T("0x%x|m_NumVersion|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_NUM_VERSION),m_NumVersion.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_NumVersion"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_NumVersion.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_NumVersion"));
	m_NumVersion.bSetVal(NUM_LAST_VERSION);
	// state SAV
	_stprintf(szText2,_T("0x%x|m_bStateMaintenance|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_MAINTENANCE),m_bStateMaintenance.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_bStateMaintenance"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_bStateMaintenance.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_bStateMaintenance"));
	// state calib
	_stprintf(szText2,_T("0x%x|m_bStateCalib|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_CALIB),m_bStateCalib.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_bStateCalib"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_bStateCalib.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_bStateCalib"));

	// state calib2
	_stprintf(szText2,_T("0x%x|m_bStateCalibInLine|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_CALIB_IN_LINE),m_bStateCalibInLine.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_bStateCalibInLine"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_bStateCalibInLine.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_bStateCalibInLine"));

	// state zero 
	_stprintf(szText2,_T("0x%x|m_bStateZero|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_ZERO),m_bStateZero.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_bStateZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_bStateZero.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_bStateZero"));
	// state cleanup
	_stprintf(szText2,_T("0x%x|m_bStateCleanup|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATE_CLEANUP),m_bStateCleanup.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_bStateCleanup"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_bStateCleanup.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_bStateCleanup"));
	// status analyseur
	_stprintf(szText2,_T("0x%x|m_bStatusFailure|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATUS_FAILURE),m_bStatusFailure.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_bStatusFailure"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_bStatusFailure.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_bStatusFailure"));
	m_bStatusFailure.bSetVal(0);

	//Status de la supervision
	_stprintf(szText2,_T("0x%x|m_bStatusSupervision|1|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_STATUS_SUPPERVISION),m_bStatusSupervision.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_bStatusSupervision"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_bStatusSupervision.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_bStatusSupervision"));
	m_bStatusSupervision.bSetVal(1);
	//m_TimeRemaingUntilNextCycle
	_stprintf(szText2,_T("0x%x|m_TimeRemaingUntilNextCycle|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT16,eID_LISTSTREAM_TIMER),m_TimeRemaingUntilNextCycle.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_TimeRemaingUntilNextCycle"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_TimeRemaingUntilNextCycle.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_TimeRemaingUntilNextCycle"));
	m_TimeRemaingUntilNextCycle.bSetVal(0);
	// durée du cycle en cours 
	_stprintf(szText2,_T("0x%x|m_CurrentTimeCycle|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CURRENT_TIME_CYCLE),m_CurrentTimeCycle.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CurrentTimeCycle"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CurrentTimeCycle.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CurrentTimeCycle"));
	m_CurrentTimeCycle.bSetVal(0);
	// status des commandes temps-reel
	_stprintf(szText2,_T("0x%x|m_bStatusRealTime|0|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT16,eID_LISTSTREAM_STATUS_REALTIME),m_bStatusRealTime.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_bStatusRealTime"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_bStatusRealTime.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_bStatusRealTime"));
	m_bStatusRealTime.bSetVal(0);

	// m_CellTemperatureOrder
	_stprintf(szText2,_T("0x%08x|m_CellTemperatureOrder|1.|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,eID_LISTSTREAM_CELL_TEMPERATURE_ORDER),m_CellTemperatureOrder.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CellTemperatureOrder"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CellTemperatureOrder.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CellTemperatureOrder"));
	// m_CellTemperatureOffset
	_stprintf(szText2,_T("0x%08x|m_CellTemperatureOffset|1.|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,eID_LISTSTREAM_CELL_OFFSET),m_CellTemperatureOffset.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_CellTemperatureOffset"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_CellTemperatureOffset.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_CellTemperatureOffset"));
	
	// m_Average
	_stprintf(szText2,_T("0x%08x|m_Average|1.|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_AVERAGE),m_Average.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_Average"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_Average.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_Average"));

	_stprintf(szText2,_T("0x%08x|m_GainProbe|1.|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,eID_LISTSTREAM_PROBE_GAIN),m_GainProbe.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_GainProbe"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_GainProbe.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_GainProbe"));
	
	_stprintf(szText2,_T("0x%08x|m_OffsetProbe|1.|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_FLOAT,eID_LISTSTREAM_PROBE_OFFSET),m_OffsetProbe.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_OffsetProbe"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_OffsetProbe.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_OffsetProbe"));

	// num de cycle du sequenceur
	for (i = 0; i < NBR_SEQUENCE_CYCLE_MAX;i++) 
	{
		if (m_ListSequenceNum.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt8())
			{
				m_ListSequenceNum.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
	}
	_stprintf(szText2,_T("0x%x|m_ListSequenceNum|0|1|2|3"),MAKE_ID(0xFF,0xFF,eTYPE_LIST,eID_LISTSTREAM_LIST_SEQUENCE_NUM));
	dwGetPrivateProfileString(_T("CListStream"),_T("m_ListSequenceNum"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_ListSequenceNum.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_ListSequenceNum"));
	// durée du cycle dans le sequenceur
	for (i = 0; i < NBR_SEQUENCE_CYCLE_MAX;i++) 
	{
		if (m_ListSequenceDuree.pGetAt(i) == NULL)
		{
			if (pElem = new CElemInt16())
			{
				m_ListSequenceDuree.pAdd(pElem);
				pElem->SetAutoDelete(TRUE);
			}
			else bReturn = FALSE;
		}
	}
	_stprintf(szText2,_T("0x%x|m_ListSequenceDuree|10|11|20|30"),MAKE_ID(0xFF,0xFF,eTYPE_LIST,eID_LISTSTREAM_LIST_SEQUENCE_DUREE));
	dwGetPrivateProfileString(_T("CListStream"),_T("m_ListSequenceDuree"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_ListSequenceDuree.bSetConfig(szText);
	if (!bReturn) _stprintf(szFailureField,_T("m_ListSequenceDuree"));
	// liste des messages d'erreur
	_stprintf(szText2,_T("0x%x|m_ListMessageError"),MAKE_ID(0xFF,0xFF,eTYPE_LIST,eID_LISTSTREAM_LIST_MESSAGE_ERROR));
	dwGetPrivateProfileString(_T("CListStream"),_T("m_ListMessageError"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) 
	{
		bReturn = m_ListMessageError.bSetConfig(szText);
		for (i = 0; i < NBR_MSG_ERROR_MAX; i++)
		{
			m_ListMessageError.pAdd(new CElemBase());
		}
	}


	iNbrVoie = iGetPrivateProfileInt(_T("CListStream"),_T("m_iNbrStream"),NBR_STREAM_MAX,pszFileName);
	//for (i = 0;bReturn && (i < NBR_STREAM_MAX/*iNbrVoie*/);i++)
	for (i = 0;bReturn && (i < iNbrVoie);i++)
	{
		pStream = pGetAt(i);
		if (pStream == NULL) pStream = pNew();
		if (bReturn = (pStream != NULL))
		{
			bReturn = pStream->bReadConfig(i, pszFileName,this);
		}
	}

	if (!bReturn) 
	{
		TRACE_DEBUG(eError,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Erreur sur %s dans la section %s"),szFailureField,szGetLabel());
		TRACE_DEBUG_IHM(eError,eConfig,eErrorAppReadConfig);
		m_bStatusFailure.bSetVal(1);
	}
	return bReturn;
}

BOOL CListStream::bReadCycle(LPCTSTR pszFileName)
{
	BOOL bReturn = TRUE;
	int i;
	CStream *pStream;

	// lecture des cycles
	//for (i = 0;bReturn && (i < NBR_STREAM_MAX/*m_iNbrStream*/);i++)
	for (i = 0;bReturn && (i < m_iNbrStream);i++)
	{
		pStream = pGetAt(i);
		if (bReturn = (pStream != NULL))
		{
			bReturn = pStream->bReadCycle(i, pszFileName,this);
		}
	}

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eConfig,eErrorAppReadConfig);
		m_bStatusFailure.bSetVal(1);
	}
	return bReturn;
}

BOOL CListStream::bWriteConfig(LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;
	int i;
	TCHAR szText[MAX_PATH];
	CStream *pStream;

	// parametres de DEBUG et TRACE
	bReturn = bWritePrivateProfileString(_T("Divers"),_T("_szLogFileDir"),_szLogFileDir,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(_T("Divers"),_T("_szLogErrorPrgFileDir"),_szLogErrorPrgFileDir,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(_T("Divers"),_T("_szUserLogFileDir"),_szUserLogFileDir,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("TRACE_DEBUG"),_T("_bTraceScreen"),_bTraceScreen,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("TRACE_DEBUG"),_T("_bDebugView"),_bDebugView,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("TRACE_DEBUG"),_T("_bLogFile"),_bLogFile,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("TRACE_DEBUG"),_T("_bErrFile"),_bErrFile,pszFileName);

	if (bReturn) bReturn = bWritePrivateProfileInt(_T("TRACE_DEBUG"),_T("_bShowError"),_bShowError,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("TRACE_DEBUG"),_T("_bShowWarning"),_bShowWarning,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("TRACE_DEBUG"),_T("_bShowInformation"),_bShowInformation,pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileInt(_T("TRACE_DEBUG"),_T("_bShowDebug"),_bShowDebug,pszFileName);

	// temps de cycle courant
	// utile pour info sur pas en cours
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CurrentStep"),CElemCycle::m_CurrentStep.szGetConfig(szText,MAX_PATH),pszFileName);

	// cmd m_CmdSaveNumConfig
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdSaveNumConfig"),m_CmdSaveNumConfig.szGetConfig(szText,MAX_PATH),pszFileName);
	// cmd m_CmdLoadNumConfig
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdLoadNumConfig"),m_CmdLoadNumConfig.szGetConfig(szText,MAX_PATH),pszFileName);
	// cmd run/stop a chaque sauvegarde, on force le cmd run à 1
	_stprintf(szText,_T("0x%x|CmdRun|1|.|%s"),MAKE_ID(0xFF,0xFF,eTYPE_INT8,eID_LISTSTREAM_CMD_RUN),m_CmdRun.m_szFormat.szGetLabel());
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdRun"),szText,pszFileName);
	// cmd pause
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdPause"),m_CmdPause.szGetConfig(szText,MAX_PATH),pszFileName);
	// cmd cycle calib
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdCycleCalib"),m_CmdCycleCalib.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdCycleCalibInLine"),m_CmdCycleCalibInLine.szGetConfig(szText,MAX_PATH),pszFileName);
	// cmd cycle zero 
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdCycleZero"),m_CmdCycleZero.szGetConfig(szText,MAX_PATH),pszFileName);
	// cmd cycle cleanup
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdCycleCleanup"),m_CmdCycleCleanup.szGetConfig(szText,MAX_PATH),pszFileName);
	// cmd jump step
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdJumpStep"),m_CmdJumpStep.szGetConfig(szText,MAX_PATH),pszFileName);
	// cmd remote control
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdRemoteControl"),m_CmdRemoteControl.szGetConfig(szText,MAX_PATH),pszFileName);
	// cmd stop fin de cycle
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdStopEndCycle"),m_CmdStopEndCycle.szGetConfig(szText,MAX_PATH),pszFileName);

	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CmdMaintenanceManuel"),m_CmdMaintenanceManuel.szGetConfig(szText,MAX_PATH),pszFileName);

	// num voie courante
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_NumCurrentStream"),m_NumCurrentStream.szGetConfig(szText,MAX_PATH),pszFileName);
	// num config courante
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_NumCurrentConfig"),m_NumCurrentConfig.szGetConfig(szText,MAX_PATH),pszFileName);
	// num version
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_NumVersion"),m_NumVersion.szGetConfig(szText,MAX_PATH),pszFileName);
	// state SAV
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_bStateMaintenance"),m_bStateMaintenance.szGetConfig(szText,MAX_PATH),pszFileName);
	// state calib
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_bStateCalib"),m_bStateCalib.szGetConfig(szText,MAX_PATH),pszFileName);
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_bStateCalibInLine"),m_bStateCalibInLine.szGetConfig(szText,MAX_PATH),pszFileName);
	// state zero
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_bStateZero"),m_bStateZero.szGetConfig(szText,MAX_PATH),pszFileName);
	// state cleanup
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_bStateCleanup"),m_bStateCleanup.szGetConfig(szText,MAX_PATH),pszFileName);
	// status analyseur
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_bStatusFailure"),m_bStatusFailure.szGetConfig(szText,MAX_PATH),pszFileName);
	//status suppervision
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_bStatusSupervision"),m_bStatusSupervision.szGetConfig(szText,MAX_PATH),pszFileName);
	//m_TimeRemaingUntilNextCycle
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_TimeRemaingUntilNextCycle"),m_TimeRemaingUntilNextCycle.szGetConfig(szText,MAX_PATH),pszFileName);
	// durée du cycle en cours 
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CurrentTimeCycle"),m_CurrentTimeCycle.szGetConfig(szText,MAX_PATH),pszFileName);
	// status realtime des programmes
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_bStatusRealTime"),m_bStatusRealTime.szGetConfig(szText,MAX_PATH),pszFileName);
	// num de cycle du sequenceur
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_ListSequenceNum"),m_ListSequenceNum.szGetConfig(szText,MAX_PATH),pszFileName);
	// duree de cycle dans sequenceur
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_ListSequenceDuree"),m_ListSequenceDuree.szGetConfig(szText,MAX_PATH),pszFileName);
		
	
	
	// message erreur : il faut les supprimer avant
	m_ListMessageError.RemoveAll();
	bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_ListMessageError"),m_ListMessageError.szGetConfig(szText,MAX_PATH),pszFileName);

	// m_CellTemperatureOrder 
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CellTemperatureOrder"),m_CellTemperatureOrder.szGetConfig(szText,MAX_PATH),pszFileName);
	// m_CellTemperatureOffset
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_CellTemperatureOffset"),m_CellTemperatureOffset.szGetConfig(szText,MAX_PATH),pszFileName);
	//m_Average
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_Average"),m_Average.szGetConfig(szText,MAX_PATH),pszFileName);
	
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_GainProbe"),m_GainProbe.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(_T("CListStream"),_T("m_OffsetProbe"),m_OffsetProbe.szGetConfig(szText,MAX_PATH),pszFileName);

	

	if (bReturn) bReturn = bWritePrivateProfileInt(_T("CListStream"),_T("m_iNbrStream"),m_iNbrStream,pszFileName);
	for (i = 0; bReturn && (i < m_iNbrStream);i++)
	{
		pStream = pGetAt(i);
		bReturn = (pStream != NULL);
		if (bReturn)
		{
			pStream->bWriteConfig(i,pszFileName);
		}
	}
	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		TRACE_DEBUG_IHM(eError,eConfig,eErrorAppWriteConfig);
		m_bStatusFailure.bSetVal(1);
	}
	return bReturn;
}



void CListStream::SetRemoteControl()
{
	if (m_ExternalInterface.m_pSocketIHM) m_ExternalInterface.m_pSocketIHM->SetAccess(TRUE,TRUE);
	if (m_CmdRemoteControl.ucGetVal() == eREMOTE_DEFAULT)
	{
	//  TRACE_LOG_MSG(_T("CListStream::SetRemoteControl eREMOTE_DEFAULT"));
		// config par Defaut
		if (m_ExternalInterface.m_pCarteIO) m_ExternalInterface.m_pCarteIO->SetAccess(FALSE,TRUE);
		if (m_ExternalInterface.m_pCarteJbusSlave) m_ExternalInterface.m_pCarteJbusSlave->SetAccess(TRUE,FALSE);
	}
	else if (m_CmdRemoteControl.ucGetVal() == eREMOTE_SAV)
	{
	//	TRACE_LOG_MSG(_T("CListStream::SetRemoteControl eREMOTE_SAV"));

		// config maintenance
		if (m_ExternalInterface.m_pCarteIO) m_ExternalInterface.m_pCarteIO->SetAccess(FALSE,FALSE);//TRUE);
		if (m_ExternalInterface.m_pCarteJbusSlave) m_ExternalInterface.m_pCarteJbusSlave->SetAccess(TRUE,FALSE);
	}
	else if (m_CmdRemoteControl.ucGetVal() == eREMOTE_JBUS_SLAVE)
	{
	//	TRACE_LOG_MSG(_T("CListStream::SetRemoteControl eREMOTE_JBUS_SLAVE"));
		// config jbus slave 
		if (m_ExternalInterface.m_pCarteIO) m_ExternalInterface.m_pCarteIO->SetAccess(FALSE,TRUE);
		if (m_ExternalInterface.m_pCarteJbusSlave) m_ExternalInterface.m_pCarteJbusSlave->SetAccess(TRUE,TRUE);
	}
	else if (m_CmdRemoteControl.ucGetVal() == eREMOTE_JBUS_MASTER)
	{
	//	TRACE_LOG_MSG(_T("CListStream::SetRemoteControl eREMOTE_JBUS_MASTER"));
		// config jbus master 
		if (m_ExternalInterface.m_pCarteIO) m_ExternalInterface.m_pCarteIO->SetAccess(TRUE,TRUE);
		if (m_ExternalInterface.m_pCarteJbusSlave) m_ExternalInterface.m_pCarteJbusSlave->SetAccess(TRUE,FALSE);
	}
	//m_bStateMaintenance.bSetVal(m_CmdRemoteControl.ucGetVal() == eREMOTE_SAV);
	//if (m_ExternalInterface.m_pCarteIO) m_ExternalInterface.m_pCarteIO->SetPause(m_CmdRemoteControl.ucGetVal() == eREMOTE_SAV);
}

void CListStream::GestionConfig()
{
	TCHAR szText[MAX_PATH];
	TCHAR szText2[MAX_PATH];
	TCHAR szText3[MAX_PATH];

	if (m_CmdLoadNumConfig.ucGetVal() != m_NumCurrentConfig.ucGetVal())
	{
		_stprintf(szText,_T("config_%d.ini"),m_CmdLoadNumConfig.ucGetVal());
		if (bReadConfig(szGetFullPathName(szText,szText2)))
		{
			bCopyFile(szGetFullPathName(szText,szText2),szGetFullPathName(_T("config.ini"),szText3),FALSE);
		}
		else
		{
			bReadConfig(szGetFullPathName(_T("config.ini"),szText2));
		}
		m_CmdSaveNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
		m_CmdLoadNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
	}
	if (m_CmdSaveNumConfig.ucGetVal() != m_NumCurrentConfig.ucGetVal())
	{
		_stprintf(szText,_T("config_%d.ini"),m_CmdSaveNumConfig.ucGetVal());
		if (bWriteConfig(szGetFullPathName(szText,szText2)))
		{
			m_NumCurrentConfig.bSetVal(m_CmdSaveNumConfig.ucGetVal());
			bWritePrivateProfileString(_T("CListStream"),_T("m_NumCurrentConfig"),m_NumCurrentConfig.szGetConfig(szText3,MAX_PATH),szGetFullPathName(szText,szText2));
			bCopyFile(szGetFullPathName(szText,szText2),szGetFullPathName(_T("config.ini"),szText3),FALSE);
		}
		else
		{
			bReadConfig(szGetFullPathName(_T("config.ini"),szText2));
		}
		m_CmdSaveNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
		m_CmdLoadNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
	}
}

void CListStream::GestionConfigFlash()
{
	TCHAR szText[MAX_PATH];
	TCHAR szText2[MAX_PATH];

	if (m_CmdLoadNumConfig.ucGetVal() != m_NumCurrentConfig.ucGetVal())
	{
		m_bStatusSupervision.bSetVal(1);
		_stprintf(szText,_T("config_%d.ini"),m_CmdLoadNumConfig.ucGetVal());
		if (bCopyFile(szGetFullPathName(szText,szText2),SZ_FIC_TEMP,FALSE))
		{
			if (bReadConfig(SZ_FIC_TEMP))
			{
				bCopyFile(SZ_FIC_TEMP,szGetFullPathName(_T("config.ini"),szText2),FALSE);
			}
			else
			{
				bCopyFile(szGetFullPathName(_T("config.ini"),szText2),SZ_FIC_TEMP,FALSE);
				bReadConfig(SZ_FIC_TEMP);
			}
		}
		m_CmdSaveNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
		m_CmdLoadNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
		m_CmdRun.bSetVal(0);
		m_CmdStopEndCycle.bSetVal(0);
		m_CmdMaintenanceManuel.bSetVal(0);
		m_bStateCalib.bSetVal(0);
		m_bStateCalibInLine.bSetVal(0);
		m_bStateZero.bSetVal(0);
		m_bStateCleanup.bSetVal(0);
		m_bStatusFailure.bSetVal(0);
		m_bStatusRealTime.bSetVal(0);
		m_CmdCycleCalib.bSetVal(0xFF);
		m_CmdCycleCalibInLine.bSetVal(0xFF);
		m_CmdCycleZero.bSetVal(0xFF);
		m_CmdCycleCleanup.bSetVal(0xFF);
		m_bStatusSupervision.bSetVal(0);

	}
	if (m_CmdSaveNumConfig.ucGetVal() != m_NumCurrentConfig.ucGetVal())
	{
		m_bStatusSupervision.bSetVal(1);
		// test si carte existe
		if (bCopyFile(szGetFullPathName(_T("config.ini"),szText2),SZ_FIC_TEMP,FALSE))
		{
			DeleteFile(SZ_FIC_TEMP);
			_stprintf(szText,_T("config_%d.ini"),m_CmdSaveNumConfig.ucGetVal());
			m_CmdLoadNumConfig.bSetVal(m_CmdSaveNumConfig.ucGetVal());

			if (bWriteConfig(SZ_FIC_TEMP))
			{
				m_NumCurrentConfig.bSetVal(m_CmdSaveNumConfig.ucGetVal());
				//bWritePrivateProfileString(_T("CListStream"),_T("m_NumCurrentConfig"),m_CmdSaveNumConfig.szGetConfig(szText2,MAX_PATH),SZ_FIC_TEMP);
				bWritePrivateProfileString(_T("CListStream"),_T("m_NumCurrentConfig"),m_NumCurrentConfig.szGetConfig(szText2,MAX_PATH),SZ_FIC_TEMP);
				if (bCopyFile(SZ_FIC_TEMP,szGetFullPathName(szText,szText2),FALSE) && 
					bCopyFile(SZ_FIC_TEMP,szGetFullPathName(_T("config.ini"),szText2),FALSE))
				{
					m_NumCurrentConfig.bSetVal(m_CmdSaveNumConfig.ucGetVal());
				}
			}
		}
		m_CmdSaveNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
		m_CmdLoadNumConfig.bSetVal(m_NumCurrentConfig.ucGetVal());
		m_bStatusSupervision.bSetVal(0);
	}

	
}

void CListStream::ExecuteCalib()
{
	DWORD dwTickCountInit;
	CMesure *pMesure;
	CMesure *pMesure2;
	CStream *pStream = NULL;
	CStream *pStream2 = NULL;
	int j,k,iOldRemoteState;
	BOOL bReturn;

	TCHAR szTrace[500];

	// reset du temps passé dans le cycle
	m_CurrentTimeCycle.bSetVal(0);
	dwTickCountInit = GetTickCount();
	CElemCycle::m_CurrentStep.m_Step.bSetVal(0);

	pStream = pGetAt(m_CmdCycleCalib.ucGetVal());
	if (pStream&& (pStream->m_Active.ucGetVal() != 0))
	{
		pStream->m_CycleTimeMax.bSetVal(pStream->m_ElemCycleCalib.m_Duration.nGetVal());
		m_NumCurrentStream.bSetVal(m_CmdCycleCalib.ucGetVal());
		m_bStateCalib.bSetVal(1);
		
		//Cycle à blanc
		for(pStream->m_ConditioningCalib.bSetVal(pStream->m_ConditioningCycleCalib.ucGetVal());
			pStream->m_ConditioningCalib.ucGetVal() > 0 && !m_CmdMaintenanceManuel.ucGetVal();
			pStream->m_ConditioningCalib.bSetVal(pStream->m_ConditioningCalib.ucGetVal()-1))
		{
			_stprintf(szTrace,_T("Conditionement calib : %d ,cpt : %d , voie : %d \n")
							,pStream->m_ConditioningCycleCalib.ucGetVal()
							, pStream->m_ConditioningCalib.ucGetVal()
							, m_CmdCycleCalib.ucGetVal());
			TRACE_LOG_MSG(szTrace);

			pStream->m_StateConditioning.bSetVal(1);
			//Attente de 2 secondes pour avoir le temps de faire un dernier cycle IO avant de passer en mode SAV
			Sleep(2000);
			iOldRemoteState = m_CmdRemoteControl.ucGetVal();
			m_CmdRemoteControl.bSetVal(eREMOTE_SAV);
			bReturn = pStream->m_ElemCycleCalib.bExecute(&m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause,&m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle,m_ExternalInterface,pStream, &this->m_NumCurrentStream);
			m_CmdRemoteControl.bSetVal(iOldRemoteState);
			
		}
		TRACE_LOG_MSG(_T("Debut calib...  \n"));
		pStream->m_StateConditioning.bSetVal(0);

		bReturn = pStream->m_ElemCycleCalib.bExecute(&m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause,&m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle,m_ExternalInterface,pStream, &this->m_NumCurrentStream);
		if (bReturn)
		{
			m_bNeedConditioning = TRUE;

			for (j = 0; j < this->iGetNbrStream();j++)
			{
				pStream2 = pGetAt(j);
				if (pStream2 && (pStream2 != pStream))
				{
					for (k = 0; k < pStream->iGetNbrMesure();k++)
					{
						pMesure = pStream->pGetAt(k);
						pMesure2 = pStream2->pGetAt(k);
						if (pMesure && pMesure2)
						{
							if ( (pMesure->m_ValMax.fGetVal() == pMesure2->m_ValMax.fGetVal()) &&
								 (lstrcmp(pMesure->m_Val.m_szUnit.szGetLabel(),pMesure2->m_Val.m_szUnit.szGetLabel()) == 0) &&
								 (lstrcmp(pMesure->m_Val.szGetLabel(),pMesure2->m_Val.szGetLabel()) == 0) )
							{
								// mise à jour de tous les coeffs
								pMesure2->m_CalibCoeff.bSetVal(pMesure->m_CalibCoeff.fGetVal());

								pMesure2->m_CalibZeroAir.bSetVal(pMesure->m_CalibZeroAir.fGetVal());
								pMesure2->m_CalibZeroWater.bSetVal(pMesure->m_CalibZeroWater.fGetVal());
							}
						}
					}
				}
			}
		}
		else
		{
			TRACE_DEBUG_IHM(eError,eCycle,eErrorCycleCalibExecute);
			m_bStatusFailure.bSetVal(1);
		}
		m_bStateCalib.bSetVal(0);
	}
}

void CListStream::ExecuteCalibInLine()
{
	DWORD dwTickCountInit;
	CMesure *pMesure;
	CMesure *pMesure2;
	CStream *pStream = NULL;
	CStream *pStream2 = NULL;
	int j;
	int k;
	int iOldRemoteState;

	BOOL bReturn;

	TCHAR szTrace[500];

	// reset du temps passé dans le cycle
	m_CurrentTimeCycle.bSetVal(0);
	dwTickCountInit = GetTickCount();
	CElemCycle::m_CurrentStep.m_Step.bSetVal(0);

	pStream = pGetAt(m_CmdCycleCalibInLine.ucGetVal());
	if (pStream&& (pStream->m_Active.ucGetVal() != 0))
	{
		pStream->m_CycleTimeMax.bSetVal(pStream->m_ElemCycleCalibInLine.m_Duration.nGetVal());
		m_NumCurrentStream.bSetVal(m_CmdCycleCalibInLine.ucGetVal());
		m_bStateCalibInLine.bSetVal(1);

		//Cycle à blanc
		for(pStream->m_ConditioningCalibInLine.bSetVal(pStream->m_ConditioningCycleCalibInLine.ucGetVal());
			pStream->m_ConditioningCalibInLine.ucGetVal() > 0 && !m_CmdMaintenanceManuel.ucGetVal();
			pStream->m_ConditioningCalibInLine.bSetVal(pStream->m_ConditioningCalibInLine.ucGetVal()-1))
		{
			_stprintf(szTrace,_T("Conditionement calibInLine : %d ,cpt : %d , voie : %d \n")
							,pStream->m_ConditioningCycleCalibInLine.ucGetVal()
							, pStream->m_ConditioningCalibInLine.ucGetVal()
							, m_CmdCycleCalibInLine.ucGetVal());
			TRACE_LOG_MSG(szTrace);

			pStream->m_StateConditioning.bSetVal(1);
			//Attente de 2 secondes pour avoir le temps de faire un dernier cycle IO avant de passer en mode SAV
			Sleep(2000);
			iOldRemoteState = m_CmdRemoteControl.ucGetVal();
			m_CmdRemoteControl.bSetVal(eREMOTE_SAV);
			bReturn = pStream->m_ElemCycleCalibInLine.bExecute(&m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause,&m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle,m_ExternalInterface,pStream, &this->m_NumCurrentStream);
			m_CmdRemoteControl.bSetVal(iOldRemoteState);
			
		}
		TRACE_LOG_MSG(_T("Debut calibInLine...  \n"));
		pStream->m_StateConditioning.bSetVal(0);

		bReturn = pStream->m_ElemCycleCalibInLine.bExecute(&m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause,&m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle,m_ExternalInterface,pStream, &this->m_NumCurrentStream);
		if (bReturn)
		{
			m_bNeedConditioning = TRUE;
			for (j = 0; j < this->iGetNbrStream();j++)
			{
				pStream2 = pGetAt(j);
				if (pStream2 && (pStream2 != pStream))
				{
					for (k = 0; k < pStream->iGetNbrMesure();k++)
					{
						pMesure = pStream->pGetAt(k);
						pMesure2 = pStream2->pGetAt(k);
						if (pMesure && pMesure2)
						{
							if ( (pMesure->m_ValMax.fGetVal() == pMesure2->m_ValMax.fGetVal()) &&
								 (lstrcmp(pMesure->m_Val.m_szUnit.szGetLabel(),pMesure2->m_Val.m_szUnit.szGetLabel()) == 0) &&
								 (lstrcmp(pMesure->m_Val.szGetLabel(),pMesure2->m_Val.szGetLabel()) == 0) )
							{
								// mise à jour de tous les coeffs
								pMesure2->m_CalibCoeff.bSetVal(pMesure->m_CalibCoeff.fGetVal());

								pMesure2->m_CalibZeroAir.bSetVal(pMesure->m_CalibZeroAir.fGetVal());
								pMesure2->m_CalibZeroWater.bSetVal(pMesure->m_CalibZeroWater.fGetVal());
							}
						}
					}
				}
			}
		}
		else
		{
			TRACE_DEBUG_IHM(eError,eCycle,eErrorCycleCalibExecute);
			m_bStatusFailure.bSetVal(1);
		}
		m_bStateCalibInLine.bSetVal(0);
	}
}
void CListStream::ExecuteZero()
{
	DWORD dwTickCountInit;
	CMesure *pMesure;
	CMesure *pMesure2;
	CStream *pStream = NULL;
	CStream *pStream2 = NULL;
	int j,k,iOldRemoteState;
	BOOL bReturn;
	
	//DEBUG
	TCHAR szTrace[500];
	///DEBUG


	// reset du temps passé dans le cycle
	m_CurrentTimeCycle.bSetVal(0);
	dwTickCountInit = GetTickCount();
	CElemCycle::m_CurrentStep.m_Step.bSetVal(0);

	pStream = pGetAt(m_CmdCycleZero.ucGetVal());
	if (pStream && (pStream->m_Active.ucGetVal() != 0)) 
	{
		pStream->m_CycleTimeMax.bSetVal(pStream->m_ElemCycleZero.m_Duration.nGetVal());
		m_NumCurrentStream.bSetVal(m_CmdCycleZero.ucGetVal());
		m_bStateZero.bSetVal(1);

		//Cycle à blanc
		for(pStream->m_ConditioningZero.bSetVal(pStream->m_ConditioningCycleZero.ucGetVal());
			pStream->m_ConditioningZero.ucGetVal() > 0 && !m_CmdMaintenanceManuel.ucGetVal();
			pStream->m_ConditioningZero.bSetVal(pStream->m_ConditioningZero.ucGetVal()-1))
		{
			_stprintf(szTrace,_T("Conditionement zero : %d ,cpt : %d , voie : %d \n")
							,pStream->m_ConditioningCycleZero.ucGetVal()
							, pStream->m_ConditioningZero.ucGetVal()
							, m_CmdCycleZero.ucGetVal());
			TRACE_LOG_MSG(szTrace);
		
			pStream->m_StateConditioning.bSetVal(1);
			//Attente de 2 secondes pour avoir le temps de faire un dernier cycle IO avant de passer en mode SAV
			Sleep(2000);
			iOldRemoteState = m_CmdRemoteControl.ucGetVal();
			m_CmdRemoteControl.bSetVal(eREMOTE_SAV);
			bReturn = pStream->m_ElemCycleZero.bExecute(&m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause,&m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle,m_ExternalInterface,pStream, &this->m_NumCurrentStream);
			m_CmdRemoteControl.bSetVal(iOldRemoteState);
			
		}
		TRACE_LOG_MSG(_T("Debut zero...  \n"));
		pStream->m_StateConditioning.bSetVal(0);

		bReturn = pStream->m_ElemCycleZero.bExecute(&m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause,&m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle,m_ExternalInterface,pStream,&this->m_NumCurrentStream);
		if (bReturn)
		{
			m_bNeedConditioning = TRUE;
			for (j = 0; j < this->iGetNbrStream();j++)
			{
				pStream2 = pGetAt(j);
				if (pStream2 && (pStream2 != pStream))
				{
					for (k = 0; k < pStream->iGetNbrMesure();k++)
					{
						pMesure = pStream->pGetAt(k);
						pMesure2 = pStream2->pGetAt(k);
						if (pMesure && pMesure2)
						{
							if ( (pMesure->m_ValMax.fGetVal() == pMesure2->m_ValMax.fGetVal()) &&
								(lstrcmp(pMesure->m_Val.m_szUnit.szGetLabel(),pMesure2->m_Val.m_szUnit.szGetLabel()) == 0) &&
								 (lstrcmp(pMesure->m_Val.szGetLabel(),pMesure2->m_Val.szGetLabel()) == 0) )
							{
								pMesure2->m_CalibZeroAir.bSetVal(pMesure->m_CalibZeroAir.fGetVal());
								pMesure2->m_CalibZeroWater.bSetVal(pMesure->m_CalibZeroWater.fGetVal());
							}
						}
					}
					//POUR KMnO4 Enregistrement de V0 et V2
					TCHAR szText1[260];
					TCHAR szText2[260];
					TCHAR szText3[260];
					pMesure = pStream->pGetAt(0);
					_stprintf(szText1,_T("config.ini"));
					szGetFullPathName(szText1,szText2);
					bWritePrivateProfileString(_T("CStream0_CMesure0")
							, _T("m_CalibZeroAir")
							, pMesure->m_CalibZeroAir.szGetConfig(szText3,MAX_PATH)
							, szGetFullPathName(szText1,szText2));
					bWritePrivateProfileString(_T("CStream0_CMesure0")
							, _T("m_Delta")
							, pMesure->m_Delta.szGetConfig(szText3,MAX_PATH)
							, szGetFullPathName(szText1,szText2));
						
					//Fin KMnO4
				}
			}
		}
		else
		{
			TRACE_DEBUG_IHM(eError,eCycle,eErrorCycleZeroExecute);
			m_bStatusFailure.bSetVal(1);
		}
		m_bStateZero.bSetVal(0);
	}
}


void CListStream::ExecuteCleanup()
{
	DWORD dwTickCountInit;
	CStream *pStream = NULL;
	BOOL bReturn;
	int iOldRemoteState;

	TCHAR szTrace[500];

	// reset du temps passé dans le cycle
	m_CurrentTimeCycle.bSetVal(0);
	dwTickCountInit = GetTickCount();
	CElemCycle::m_CurrentStep.m_Step.bSetVal(0);

	pStream = pGetAt(m_CmdCycleCleanup.ucGetVal());
	if (pStream && (pStream->m_Active.ucGetVal() != 0))
	{
		pStream->m_CycleTimeMax.bSetVal(pStream->m_ElemCycleCleanup.m_Duration.nGetVal());
		m_NumCurrentStream.bSetVal(m_CmdCycleCleanup.ucGetVal());
		m_bStateCleanup.bSetVal(1);

		//Cycle à blanc
		for(pStream->m_ConditioningCleanup.bSetVal(pStream->m_ConditioningCycleCleanup.ucGetVal());
			pStream->m_ConditioningCleanup.ucGetVal() > 0 && !m_CmdMaintenanceManuel.ucGetVal();
			pStream->m_ConditioningCleanup.bSetVal(pStream->m_ConditioningCleanup.ucGetVal()-1))
		{
			_stprintf(szTrace,_T("Conditionement cleanup : %d ,cpt : %d , voie : %d \n")
							,pStream->m_ConditioningCycleCleanup.ucGetVal()
							, pStream->m_ConditioningCleanup.ucGetVal()
							, m_CmdCycleCleanup.ucGetVal());
			TRACE_LOG_MSG(szTrace);

			pStream->m_StateConditioning.bSetVal(1);
			//Attente de 2 secondes pour avoir le temps de faire un dernier cycle IO avant de passer en mode SAV
			Sleep(2000);
			iOldRemoteState = m_CmdRemoteControl.ucGetVal();
			m_CmdRemoteControl.bSetVal(eREMOTE_SAV);
			bReturn = pStream->m_ElemCycleCleanup.bExecute(&m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause,&m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle,m_ExternalInterface,pStream, &this->m_NumCurrentStream);
			m_CmdRemoteControl.bSetVal(iOldRemoteState);
			
		}
		TRACE_LOG_MSG(_T("Debut cleanup...  \n"));
		pStream->m_StateConditioning.bSetVal(0);

		bReturn = pStream->m_ElemCycleCleanup.bExecute(&m_CmdRun,&m_CmdStopEndCycle,&m_CmdPause,&m_CmdJumpStep,&m_bStatusRealTime,&m_CurrentTimeCycle,m_ExternalInterface,pStream, &this->m_NumCurrentStream);
		m_bNeedConditioning = TRUE;
		if (!bReturn)
		{
			TRACE_DEBUG_IHM(eError,eCycle,eErrorCycleCleanupExecute);
			m_bStatusFailure.bSetVal(1);
		}
		m_bStateCleanup.bSetVal(0);
	}
}


// gestion des cycles
void CListStream::Stop()
{
	m_CmdRun.bSetVal((BYTE)0);
	CThread::Stop();
	m_ListMessageError.RemoveAll();
}


// gestion des cycles
DWORD CListStream::RunThread()
{
	m_bRun = TRUE;
	while (m_CmdRun.ucGetVal())
	{
		SetRemoteControl();
		if (m_ExternalInterface.m_pCarteIO->bGetError() || m_ExternalInterface.m_pCarteJbusSlave->bGetError())
		{
			TRACE_DEBUG_IHM(eError,eCycle,eErrorAppRunThread);
			m_bStatusFailure.bSetVal(1);
		}
	}

	return 0;
}



