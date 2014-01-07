#pragma once
#include "network.h"

#ifndef __FUNCTION__
#define __FUNCTION__      "unknown"
#endif



typedef enum eTypeMsgTrace {
	eError = 0,  
	eWarning ,
	eInformation,
	eDebug,
};

typedef enum eOrigineMsgTrace {
	eConfig = 0,
	eComSerial,
	eComJBus,
	eComJBusMaster,
	eComMesure,
	eComJBusSlave,
	eComSocket,
	eCycle,
	eCycleCalib,
	eCycleZero,
	eCycleCleanup,
	eMesure,
};

typedef enum eMsgErrorIHM {
	eErrorFindRqAndExecuteFromIHM = 0,// doit toujours demarrer a partir de zero
	eErrorCycleReadConfig,
	eErrorCycleWriteConfig,
	eErrorCycleExecute,
	eErrorCycleZeroReadConfig,
	eErrorCycleZeroWriteConfig,
	eErrorCycleZeroExecute,
	eErrorCycleCalibReadConfig,
	eErrorCycleCalibWriteConfig,
	eErrorCycleCalibExecute,
	eErrorCycleCleanupReadConfig,
	eErrorCycleCleanupWriteConfig,
	eErrorCycleCleanupExecute,
	eErrorSocketReadConfig,
	eErrorSocketWriteConfig,
	eErrorSocketRunThread,
	eErrorAppReadConfig,
	eErrorAppWriteConfig,
	eErrorAppRunThread,
	eErrorCarteIOReadConfig,
	eErrorCarteIOWriteConfig,
	eErrorCarteIOExecute,
	eErrorCarteJBusSlaveReadConfig,
	eErrorCarteJBusSlavebWriteConfig,
	eErrorCarteJBusSlaveRead,
	eErrorCarteJBusSlaveDispatchTrame,
	eErrorCarteMesureReadConfig,
	eErrorCarteMesureWriteConfig,
	eErrorMesureStatusThreshold1,
	eErrorMesureStatusThreshold2,
	eErrorMesureValMax,
	eErrorMesureValMin,
	eErrorPrgRegulControlLuggageHeatingUnattained,
	eErrorPrgRegulControlHeatingTemperatureUnstable, 
	eErrorPrgWaterDefaultLackOfWater,
	eErrorPrgWaterDefaultDefaultMeasure,
	eErrorPrgDefaultOpticalSetting,
	eErrorPrgDefaultIncorrectOpticalSetting,
	eErrorPrgDefaultCurrentProjector,
	eErrorPrgOpticalMeasureDefaultMeasure,
	eErrorPrgOpticalMeasureDefaultStability,
	eErrorPrgAbsorbanceCalculDivByZero,
	eErrorPrgConcentrationCalculDivByZero,
	eErrorPrgConcentrationCalculOutOfBound,
	eErrorPrgCalibrationCoefCalculDivByZero,
	eErrorPrgCalibrationCoefCalculOutOfBound,
	eErrorPrgLinearisationDivByZero,
	eErrorPrgLinearisationOutOfRange,
	eErrorPrgInverseLinDivByZero,
	eErrorPrgInverseLinOutOfRange,
	eErrorPrgConfigInitNegativeGain,
	eErrorPrgCalibrationCoefCalculM2DivByZero,
	eErrorPrgCalibrationCoefCalculM2OutOfGap,
	eErrorPrgOffsetZeroCalculDivByZero,
	eErrorPrgOffsetZeroCalculOutOfBound,
	eErrorPrgConfigInitNegativeProbeGain,
	eErrorPrgHeatWaterControlDefaultHeatWater,
	eErrorPrg203,
	eErrorPrg205,
	eErrorPrg213, 
	eErrorPrg215, 
	eErrorPrg219, 
	eErrorPrg223, 
	eErrorPrg225, 
	eErrorPrg229, 
	eErrorPrg22D, 
	eErrorPrg233, 
	eErrorPrg235, 
	eErrorPrg243, 
	eErrorPrg245, 
	eErrorPrg253, 
	eErrorPrg255, 
	eErrorPrg259, 
	eErrorPrg443, 
	eErrorPrg453, 
	eErrorPrg463, 
	eErrorPrg465,
	eErrorPrg173,
	eErrorPrg393,
	eErrorPrg403,
	eErrorPrg405,
	eErrorPrg413,
	eErrorLast,  // doit toujours être en dernier
};

NETWORK_API void TRACE_DEBUG(int eTypeMsg,int eOrigineMsg, LPCTSTR szFile, LPCTSTR szFunction, int	noLigne, LPCTSTR format, ... );
NETWORK_API void TRACE_DEBUG_LAST_ERROR(int eTypeMsg,int eOrigineMsg,DWORD dwErrNbr);
NETWORK_API void TRACE_DEBUG_IHM(int eTypeMsg,int eOrigineMsg, int eErrorCode);
NETWORK_API void TRACE_LOG_MESURE(CStream* argObjVoie, CElemInt8* argNumCurrentStream, int argiMoyenne);
NETWORK_API void TRACE_LOG_ERROR_PRG(CStream* argObjVoie, CElemInt8* argNumCurrentStream, int argiNumMesure, int argiNumPas);
NETWORK_API void  WriteConfigMsgError(LPTSTR szFileMsg);
NETWORK_API void  ReadConfigMsgError(LPTSTR szFileMsg);
NETWORK_API void TRACE_LOG_MSG(WCHAR* argpszMessage);
NETWORK_API void TRACE_DEBUG_MSG_TIME(WCHAR* argpszMessage, int iID);
NETWORK_API extern BOOL _bShowError;  
NETWORK_API extern BOOL _bShowWarning;
NETWORK_API extern BOOL _bShowInformation;
NETWORK_API extern BOOL _bShowDebug;

NETWORK_API extern HWND _hDebugWnd;
NETWORK_API extern BOOL _bDebugView;
NETWORK_API extern BOOL _bTraceScreen;
NETWORK_API extern BOOL _bLogFile;
NETWORK_API extern BOOL _bErrFile;
NETWORK_API extern TCHAR _szLogFileDir[MAX_PATH];
NETWORK_API extern TCHAR _szLogErrorPrgFileDir[MAX_PATH];
NETWORK_API extern TCHAR _szUserLogFileDir[MAX_PATH];


//Methode local
void verifierDefaut(BYTE argcErrorToCheck, CStream* argObjVoie, int argiNumMesure, int argiNumPas, WCHAR* argpszMessage, int* argpIndexMessage, int argeError);
BOOL bEcrireFichierLog(WCHAR* argpszMessage, WCHAR* argpszFullPath, WCHAR* argpszFileName);
void szBuildFileName(WCHAR* argszFileName, WCHAR* argszExt);