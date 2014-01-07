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

 void TRACE_DEBUG(int eTypeMsg,int eOrigineMsg, LPCTSTR szFile, LPCTSTR szFunction, int	noLigne, LPCTSTR format, ... );
 void TRACE_DEBUG_LAST_ERROR(int eTypeMsg,int eOrigineMsg,DWORD dwErrNbr);
 void TRACE_DEBUG_IHM(int eTypeMsg,int eOrigineMsg, int eErrorCode, CElemInt8* argNumCurrentStream=0);
 void TRACE_LOG_MESURE(CStream* argObjVoie, CElemInt8* argNumCurrentStream, int argiMoyenne);
 void TRACE_LOG_ERROR_PRG(CStream* argObjVoie, CElemInt8* argNumCurrentStream, int argiNumMesure, int argiNumPas);
 void  WriteConfigMsgError(LPTSTR szFileMsg);
 void  ReadConfigMsgError(LPTSTR szFileMsg);
 void TRACE_LOG_MSG(WCHAR* argpszMessage);
 void TRACE_DEBUG_MSG_TIME(WCHAR* argpszMessage, int iID);
 extern BOOL _bShowError;  
 extern BOOL _bShowWarning;
 extern BOOL _bShowInformation;
 extern BOOL _bShowDebug;

 extern HWND _hDebugWnd;
 extern BOOL _bDebugView;
 extern BOOL _bTraceScreen;
 extern BOOL _bLogFile;
 extern BOOL _bErrFile;
 extern TCHAR _szLogFileDir[MAX_PATH];
 extern TCHAR _szLogErrorPrgFileDir[MAX_PATH];
 extern TCHAR _szUserLogFileDir[MAX_PATH];


//Methode local
void verifierDefaut(BYTE argcErrorToCheck, CStream* argObjVoie, int argiNumMesure, int argiNumPas, WCHAR* argpszMessage, int* argpIndexMessage, int argeError, CElemInt8* argNumCurrentStream);
BOOL bEcrireFichierLog(WCHAR* argpszMessage, WCHAR* argpszFullPath, WCHAR* argpszFileName);
void szBuildFileName(WCHAR* argszFileName, WCHAR* argszExt);