#pragma once


#define SZ_FIC_TEMP			_T("\\config_temp.ini")
#define SZ_FIC_TEMP2		_T("\\cycle_temp.ini")

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
#define NBR_MESURE_MAX  		4

class  CStream : public CElemBase
{
public:
	CStream(BYTE ucNumVoie);
	virtual ~CStream();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual void RemoveAll();

public:
	CMesure *pNew();
	CMesure *pGetAt(int iPos);
	long iGetNbrMesure(){return m_iNbrMesure;};
	BOOL bReadConfig(int iNumStream, LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bReadCycle(int iNumStream, LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bWriteConfig(int iNumStream, LPCTSTR pszFileName);
	BOOL bExecute( CElemInt8 *pCmdRun,CElemInt8 *pCmdStopEndCycle,CElemInt8 *pCmdPause
				 , CElemInt16 *pCmdJumpStep,CElemInt16 *pStatusRealTime
				 , CElemInt16 *pTimeCycle,CEnumInterface &EnumInterface
				 , CElemInt8* argNumCurrentStream, CElemInt8 * argpCmdCycleCalib, CElemInt8 * argpCmdCycleCalibInLine
			     , CElemInt8 * argpCmdCycleCleanup, CElemInt8 * argpCmdCycleZero
				 , CElemInt8 * pCmdRemoteControl, bool& argbNeedConditioning);
	BOOL bCheckAndCmdPeriodic( int& argiCheckedDays, int& argiCheckedHours
							, CElemList* argpPeriodicHourCycle, CElemList* argpPeriodicDayCycle
							, CElemInt8* argpPeriodicCycle, int& argiCptCycle
					        , CElemInt8 * argpCmdCycle, CElemInt8* argNumCurrentStream);


public:
	CElemBase m_StreamName;
	CElemInt16 m_CycleTimeMax;					// durée max du cycle		 INUTILISE ==> variable dans CListStream
	CElemInt16 m_CycleTimeCurrent;				// temps passé dans le cycle INUTILISE ==> variable dans CListStream
	CElemInt8 m_Active;							// voie active
	CElemInt8 m_StatusFailure;					// voie en défaut
	CElemInt8 m_StatusWaterFailure;				// défaut d'eau
	CElemInt8 m_IsRunning;						// cycle en cours
	CElemInt16 m_CounterCycle;					// compteur de cycle
	CElemBase m_ElemCycleFilename;
	CElemBase m_ElemCycleCleanupFilename;
	CElemBase m_ElemCycleZeroFilename;
	CElemBase m_ElemCycleCalibFilename;
	CElemBase m_ElemCycleCalibInLineFilename;
	CElemCycle m_ElemCycle;
	CElemCycleCleanup m_ElemCycleCleanup;
	CElemCycleZero m_ElemCycleZero;
	CElemCycleCalib m_ElemCycleCalib;
	CElemCycleCalib m_ElemCycleCalibInLine;

	CElemFloat m_CellTemperature;
	CElemFloat m_WaterFailureSetPoint;
	CElemInt16 m_OpticalSetPoint;
	CElemFloat m_CellTemperatureSetPoint;
	// mesure pression 
	CElemFloat m_PressureMeasurement;

	CElemFloat m_ThresholdTemperatureProbe;
	CElemFloat m_TemperatureProbe;

	CElemFloat m_SettingColorThreshold1;
	CElemFloat m_SettingColorThreshold2;

	CElemInt8 m_PeriodicCycleCleanup;
	CElemInt8 m_PeriodicCycleZero;
	CElemInt8 m_PeriodicCycleCalib;
	CElemInt8 m_PeriodicCycleCalibInLine;
	
	
	CElemList m_ListPeriodicHourCycleCleanup;
	CElemList m_ListPeriodicHourCycleZero;
	CElemList m_ListPeriodicHourCycleCalib;
	CElemList m_ListPeriodicHourCycleCalibInLine;
	
	CElemList m_ListPeriodicDayCycleCleanup;
	CElemList m_ListPeriodicDayCycleZero;
	CElemList m_ListPeriodicDayCycleCalib;
	CElemList m_ListPeriodicDayCycleCalibInLine;

	CElemInt8 m_ConditioningCycleCleanup;
	CElemInt8 m_ConditioningCycleZero;
	CElemInt8 m_ConditioningCycleCalib;
	CElemInt8 m_ConditioningCycleCalibInLine;
	CElemInt8 m_ConditioningCycleMeasurement;

	CElemInt8 m_ConditioningCleanup;
	CElemInt8 m_ConditioningZero;
	CElemInt8 m_ConditioningCalib;
	CElemInt8 m_ConditioningCalibInLine;
	CElemInt8 m_ConditioningMeasurement;

	CElemInt8 m_StateConditioning;

	int m_iNbCycleCleanup;
	int m_iNbCycleZero;
	int m_iNbCycleCalib;
	int m_iNbCycleCalibInLine;

	int m_iNbConditioningCycleCleanup;
	int m_iNbConditioningCycleZero;
	int m_iNbConditioningCycleCalib;
	int m_iNbConditioningCycleCalibInLine;

	int m_iCalibCheckedDays;
	int m_iCalibInLineCheckedDays;
	int m_iCleanupCheckedDays;
	int m_iZeroCheckedDays;
	int m_iCalibCheckedHours;
	int m_iCalibInLineCheckedHours;
	int m_iCleanupCheckedHours;
	int m_iZeroCheckedHours;

protected:
	long m_iNbrMesure;
	CMesure *m_apMesure[NBR_MESURE_MAX];
	



};

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
#define NBR_STREAM_MAX				6
#define NBR_SEQUENCE_CYCLE_MAX 		32
#define NBR_MSG_ERROR_MAX 			32


class  CListStream : public CElemBase, public CThread
{
public:
	CListStream();
	virtual ~CListStream();
	virtual void RemoveAll();

public:
	virtual void Stop();
	virtual BOOL bSerialize(CContext &Context);
	BOOL bSerialize(BOOL bSave, LPCTSTR pszFileName);
	virtual int iGetStreamSize(CContext &Context);
	CStream *pNew();
	CStream *pGetAt(int iPos);
	BOOL bReadConfig(LPCTSTR pszFileName);
	BOOL bReadTempConfig(LPCTSTR pszFileName);
	BOOL bReadCycle(LPCTSTR pszFileName);
	BOOL bWriteConfig(LPCTSTR pszFileName);
	long iGetNbrStream()const{return m_iNbrStream;};
	CElemBase *pFindElemFromID(long lID);
	CElemBase *pFindOrCreateElemFromID(long lID);
	void SetRemoteControl();
	void GestionConfig();
	void GestionConfigFlash();
	void ExecuteCalib();
	void ExecuteCalibInLine();
	void ExecuteZero();
	void ExecuteCleanup();

protected:
    //virtual DWORD RunThread();
    virtual void run();

public:
	BOOL bAnalyseurStoped;

	CElemInt8 m_CmdLoadNumConfig;
	CElemInt8 m_CmdSaveNumConfig;
	CElemInt8 m_CmdRun;
	CElemInt8 m_CmdPause;
	CElemInt8 m_CmdCycleCalib;
	CElemInt8 m_CmdCycleCalibInLine;
	CElemInt8 m_CmdCycleZero;
	CElemInt8 m_CmdCycleCleanup;
	CElemInt16 m_CmdJumpStep;
	CElemInt8 m_CmdRemoteControl;
	CElemInt8 m_CmdStopEndCycle;
	CElemInt8 m_CmdMaintenanceManuel;
	CElemInt8 m_NumCurrentConfig;
	CElemInt8 m_NumVersion;
	CElemInt8 m_NumCurrentStream;
	CElemInt8 m_bStateMaintenance;
	CElemInt8 m_bStateCalib;
	CElemInt8 m_bStateCalibInLine;
	CElemInt8 m_bStateZero;
	CElemInt8 m_bStateCleanup;
	CElemInt8 m_bStatusFailure;
	CElemInt8 m_bStatusSupervision;
	CElemInt16 m_bStatusRealTime;
	CElemInt16 m_CurrentTimeCycle;
	CElemInt16 m_TimeRemaingUntilNextCycle;
	CElemFloat m_CellTemperatureOrder; //Gain ... 
	CElemFloat m_CellTemperatureOffset;

	CElemInt8 m_Average;

	CElemFloat m_GainProbe;
	CElemFloat m_OffsetProbe;

	CEnumInterface m_ExternalInterface;
	CElemList m_ListSequenceNum;
	CElemList m_ListSequenceDuree;
	static CElemList m_ListMessageError;
protected:
	long m_iNbrStream;
	bool m_bNeedConditioning;
	CStream *m_apStream[NBR_STREAM_MAX];
};

			 




