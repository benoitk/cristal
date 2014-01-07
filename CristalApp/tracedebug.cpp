#include "stdafx.h"
#include "network.h"



BOOL _bShowError = TRUE;  
BOOL _bShowWarning = TRUE;
BOOL _bShowInformation = TRUE;
BOOL _bShowDebug = TRUE;

HWND _hDebugWnd = NULL;
BOOL _bDebugView = TRUE;
BOOL _bTraceScreen = TRUE;
BOOL _bLogFile = TRUE;
BOOL _bErrFile = TRUE;
TCHAR _szLogFileDir[MAX_PATH] = _T("\\");
TCHAR _szLogErrorPrgFileDir[MAX_PATH] = _T("\\");
TCHAR _szUserLogFileDir[MAX_PATH] = _T("\\");


#define NB_MESURE_MOYENNEE	1



static CRITICAL_SECTION _LogCriticalSection;
static TCHAR _aszErrorText[eErrorLast + 1][MAX_PATH];

static TCHAR *aszTypeMsgTrace[] = {
		_T("Error"),  
		_T("eWarning"),
		_T("eInformation"),
		_T("eDebug")};

static TCHAR *aszOrigineMsgTrace[] = {
		_T("eConfig"),
		_T("eComSerial"),
		_T("eComJBus"),
		_T("eComJBusMaster"),
		_T("eComMesure"),
		_T("eComJBusSlave"),
		_T("eComSocket"),
		_T("eCycle"),
		_T("eCycleCalib"),
		_T("eCycleZero"),
		_T("eCycleCleanup"),
		_T("eMesure"),
		};

void ReadConfigMsgError(LPTSTR szFileMsg)
{
	memset(&_aszErrorText[0][0],0,sizeof(_aszErrorText));
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorFindRqAndExecuteFromIHM"),_T("Paramètre ou variable inconnu"),_aszErrorText[eErrorFindRqAndExecuteFromIHM],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleReadConfig"),_T("Erreur de lecture de la configuration du cycle"),_aszErrorText[eErrorCycleReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleWriteConfig"),_T("Erreur d'écriture de la configuration du cycle"),_aszErrorText[eErrorCycleWriteConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleExecute"),_T("Erreur d'exécution du cycle"),_aszErrorText[eErrorCycleExecute],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleZeroReadConfig"),_T("Erreur de lecture de la configuration du cycle de zero"),_aszErrorText[eErrorCycleZeroReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleZeroWriteConfig"),_T("Erreur d'écriture de la configuration du cycle de zero"),_aszErrorText[eErrorCycleZeroWriteConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleZeroExecute"),_T("Erreur d'exécution du cycle de zero"),_aszErrorText[eErrorCycleZeroExecute],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleCalibReadConfig"),_T("Erreur de lecture de la configuration du cycle de calibration"),_aszErrorText[eErrorCycleCalibReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleCalibWriteConfig"),_T("Erreur d'écriture de la configuration du cycle de calibration"),_aszErrorText[eErrorCycleCalibWriteConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleCalibExecute"),_T("Erreur d'exécution du cycle de calibration"),_aszErrorText[eErrorCycleCalibExecute],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleCleanupReadConfig"),_T("Erreur de lecture de la configuration du cycle de nettoyage"),_aszErrorText[eErrorCycleCleanupReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleCleanupWriteConfig"),_T("Erreur d'écriture de la configuration du cycle de nettoyage"),_aszErrorText[eErrorCycleCleanupWriteConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCycleCleanupExecute"),_T("Erreur d'exécution du cycle de nettoyage"),_aszErrorText[eErrorCycleCleanupExecute],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorSocketReadConfig"),_T("Erreur de lecture de la configuration de la socket"),_aszErrorText[eErrorSocketReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorSocketWriteConfig"),_T("Erreur d'écriture de la configuration de la socket"),_aszErrorText[eErrorSocketWriteConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorSocketRunThread"),_T("Erreur d'exécution de la socket"),_aszErrorText[eErrorSocketRunThread],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorAppReadConfig"),_T("Erreur de lecture de la configuration de l'application"),_aszErrorText[eErrorAppReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorAppWriteConfig"),_T("Erreur d'écriture de la configuration de l'application"),_aszErrorText[eErrorAppWriteConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorAppRunThread"),_T("Erreur d'exécution de l'application"),_aszErrorText[eErrorAppRunThread],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteIOReadConfig"),_T("Erreur de lecture sur la carte IO"),_aszErrorText[eErrorCarteIOReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteIOWriteConfig"),_T("Erreur d'écriture sur la carte IO"),_aszErrorText[eErrorCarteIOWriteConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteIOExecute"),_T("Erreur d'exécution sur la carte IO"),_aszErrorText[eErrorCarteIOExecute],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteJBusSlaveReadConfig"),_T("Erreur de lecture de la configuration de la carte JBUS esclave"),_aszErrorText[eErrorCarteJBusSlaveReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteJBusSlavebWriteConfig"),_T("Erreur d'écriture de la configuration de la carte JBUS esclave"),_aszErrorText[eErrorCarteJBusSlavebWriteConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteJBusSlaveRead"),_T("Erreur de lecture sur la carte JBUS esclave"),_aszErrorText[eErrorCarteJBusSlaveRead],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteJBusSlaveDispatchTrame"),_T("Erreur de traitement sur la carte JBUS esclave"),_aszErrorText[eErrorCarteJBusSlaveDispatchTrame],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteMesureReadConfig"),_T("Erreur de lecture de la configuration de la carte mesure"),_aszErrorText[eErrorCarteMesureReadConfig],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorCarteMesureWriteConfig"),_T("Erreur d'écriture de la configuration de la carte mesure"),_aszErrorText[eErrorCarteMesureWriteConfig],MAX_PATH,szFileMsg);

	dwGetPrivateProfileString(_T("MSG"), _T("eErrorMesureStatusThreshold1"),_T("Erreur dépassement seuil 1"),_aszErrorText[eErrorMesureStatusThreshold1],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorMesureStatusThreshold2"),_T("Erreur dépassement seuil 2"),_aszErrorText[eErrorMesureStatusThreshold2],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorMesureValMax"),_T("Erreur dépassement valeur max"),_aszErrorText[eErrorMesureValMax],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorMesureValMin"),_T("Erreur dépassement valeur min"),_aszErrorText[eErrorMesureValMin],MAX_PATH,szFileMsg);
	
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgRegulControlLuggageHeatingUnattained"),_T("eErrorPrgRegulControlLuggageHeatingUnattained"),_aszErrorText[eErrorPrgRegulControlLuggageHeatingUnattained],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgRegulControlHeatingTemperatureUnstable"),_T("eErrorPrgRegulControlHeatingTemperatureUnstable"),_aszErrorText[eErrorPrgRegulControlHeatingTemperatureUnstable],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgWaterDefaultLackOfWater"),_T("eErrorPrgWaterDefaultLackOfWater"),_aszErrorText[eErrorPrgWaterDefaultLackOfWater],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgWaterDefaultDefaultMeasure"),_T("eErrorPrgWaterDefaultDefaultMeasure"),_aszErrorText[eErrorPrgWaterDefaultDefaultMeasure],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgDefaultOpticalSetting"),_T("eErrorPrgDefaultOpticalSetting"),_aszErrorText[eErrorPrgDefaultOpticalSetting],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgDefaultIncorrectOpticalSetting"),_T("eErrorPrgDefaultIncorrectOpticalSetting"),_aszErrorText[eErrorPrgDefaultIncorrectOpticalSetting],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgDefaultCurrentProjector"),_T("eErrorPrgDefaultCurrentProjector"),_aszErrorText[eErrorPrgDefaultCurrentProjector],MAX_PATH,szFileMsg);
	
	
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgOpticalMeasureDefaultMeasure"),_T("eErrorPrgOpticalMeasureDefaultMeasure"),_aszErrorText[eErrorPrgOpticalMeasureDefaultMeasure],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgOpticalMeasureDefaultStability"),_T("eErrorPrgOpticalMeasureDefaultStability"),_aszErrorText[eErrorPrgOpticalMeasureDefaultStability],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgAbsorbanceCalculDivByZero"),_T("eErrorPrgAbsorbanceCalculDivByZero"),_aszErrorText[eErrorPrgAbsorbanceCalculDivByZero],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgConcentrationCalculDivByZero"),_T("eErrorPrgConcentrationCalculDivByZero"),_aszErrorText[eErrorPrgConcentrationCalculDivByZero],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgConcentrationCalculOutOfBound"),_T("eErrorPrgConcentrationCalculOutOfBound"),_aszErrorText[eErrorPrgConcentrationCalculOutOfBound],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgCalibrationCoefCalculDivByZero"),_T("eErrorPrgCalibrationCoefCalculDivByZero"),_aszErrorText[eErrorPrgCalibrationCoefCalculDivByZero],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgCalibrationCoefCalculOutOfBound"),_T("eErrorPrgCalibrationCoefCalculOutOfBound"),_aszErrorText[eErrorPrgCalibrationCoefCalculOutOfBound],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgLinearisationDivByZero"),_T("eErrorPrgLinearisationDivByZero"),_aszErrorText[eErrorPrgLinearisationDivByZero],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgLinearisationOutOfRange"),_T("eErrorPrgLinearisationOutOfRange"),_aszErrorText[eErrorPrgLinearisationOutOfRange],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgInverseLinDivByZero"),_T("eErrorPrgInverseLinDivByZero"),_aszErrorText[eErrorPrgInverseLinDivByZero],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgInverseLinOutOfRange"),_T("eErrorPrgInverseLinOutOfRange"),_aszErrorText[eErrorPrgInverseLinOutOfRange],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgConfigInitNegativeGain"),_T("eErrorPrgConfigInitNegativeGain"),_aszErrorText[eErrorPrgConfigInitNegativeGain],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgCalibrationCoefCalculM2DivByZero"),_T("eErrorPrgCalibrationCoefCalculM2DivByZero"),_aszErrorText[eErrorPrgCalibrationCoefCalculM2DivByZero],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgCalibrationCoefCalculM2OutOfGap"),_T("eErrorPrgCalibrationCoefCalculM2OutOfGap"),_aszErrorText[eErrorPrgCalibrationCoefCalculM2OutOfGap],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgOffsetZeroCalculDivByZero"),_T("eErrorPrgOffsetZeroCalculDivByZero"),_aszErrorText[eErrorPrgOffsetZeroCalculDivByZero],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgOffsetZeroCalculOutOfBound"),_T("eErrorPrgOffsetZeroCalculOutOfBound"),_aszErrorText[eErrorPrgOffsetZeroCalculOutOfBound],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgConfigInitNegativeProbeGain"),_T("eErrorPrgConfigInitNegativeProbeGain"),_aszErrorText[eErrorPrgConfigInitNegativeProbeGain],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrgHeatWaterControlDefaultHeatWater"),_T("eErrorPrgHeatWaterControlDefaultHeatWater"),_aszErrorText[eErrorPrgHeatWaterControlDefaultHeatWater],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg203"),_T("eErrorPrg203"),_aszErrorText[eErrorPrg203],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg205"),_T("eErrorPrg205"),_aszErrorText[eErrorPrg205],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg213"),_T("eErrorPrg213"),_aszErrorText[eErrorPrg213],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg215"),_T("eErrorPrg215"),_aszErrorText[eErrorPrg215],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg219"),_T("eErrorPrg219"),_aszErrorText[eErrorPrg219],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg223"),_T("eErrorPrg223"),_aszErrorText[eErrorPrg223],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg225"),_T("eErrorPrg225"),_aszErrorText[eErrorPrg225],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg229"),_T("eErrorPrg229"),_aszErrorText[eErrorPrg229],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg22D"),_T("eErrorPrg22D"),_aszErrorText[eErrorPrg22D],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg233"),_T("eErrorPrg233"),_aszErrorText[eErrorPrg233],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg235"),_T("eErrorPrg235"),_aszErrorText[eErrorPrg235],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg245"),_T("eErrorPrg245"),_aszErrorText[eErrorPrg245],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg243"),_T("eErrorPrg243"),_aszErrorText[eErrorPrg243],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg253"),_T("eErrorPrg253"),_aszErrorText[eErrorPrg253],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg255"),_T("eErrorPrg255"),_aszErrorText[eErrorPrg255],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg259"),_T("eErrorPrg259"),_aszErrorText[eErrorPrg259],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg443"),_T("eErrorPrg443"),_aszErrorText[eErrorPrg443],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg453"),_T("eErrorPrg453"),_aszErrorText[eErrorPrg453],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg463"),_T("eErrorPrg463"),_aszErrorText[eErrorPrg463],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg465"),_T("eErrorPrg465"),_aszErrorText[eErrorPrg465],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg173"),_T("eErrorPrg173"),_aszErrorText[eErrorPrg173],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg393"),_T("eErrorPrg393"),_aszErrorText[eErrorPrg393],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg403"),_T("eErrorPrg403"),_aszErrorText[eErrorPrg403],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg405"),_T("eErrorPrg405"),_aszErrorText[eErrorPrg405],MAX_PATH,szFileMsg);
	dwGetPrivateProfileString(_T("MSG"), _T("eErrorPrg413"),_T("eErrorPrg413"),_aszErrorText[eErrorPrg413],MAX_PATH,szFileMsg);

}

void WriteConfigMsgError(LPTSTR szFileMsg)
{
	bWritePrivateProfileString(_T("MSG"), _T("eErrorFindRqAndExecuteFromIHM"),_aszErrorText[eErrorFindRqAndExecuteFromIHM],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleReadConfig"),_aszErrorText[eErrorCycleReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleWriteConfig"),_aszErrorText[eErrorCycleWriteConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleExecute"),_aszErrorText[eErrorCycleExecute],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleZeroReadConfig"),_aszErrorText[eErrorCycleZeroReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleZeroWriteConfig"),_aszErrorText[eErrorCycleZeroWriteConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleZeroExecute"),_aszErrorText[eErrorCycleZeroExecute],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleCalibReadConfig"),_aszErrorText[eErrorCycleCalibReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleCalibWriteConfig"),_aszErrorText[eErrorCycleCalibWriteConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleCalibExecute"),_aszErrorText[eErrorCycleCalibExecute],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleCleanupReadConfig"),_aszErrorText[eErrorCycleCleanupReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleCleanupWriteConfig"),_aszErrorText[eErrorCycleCleanupWriteConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCycleCleanupExecute"),_aszErrorText[eErrorCycleCleanupExecute],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorSocketReadConfig"),_aszErrorText[eErrorSocketReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorSocketWriteConfig"),_aszErrorText[eErrorSocketWriteConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorSocketRunThread"),_aszErrorText[eErrorSocketRunThread],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorAppReadConfig"),_aszErrorText[eErrorAppReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorAppWriteConfig"),_aszErrorText[eErrorAppWriteConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorAppRunThread"),_aszErrorText[eErrorAppRunThread],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteIOReadConfig"),_aszErrorText[eErrorCarteIOReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteIOWriteConfig"),_aszErrorText[eErrorCarteIOWriteConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteIOExecute"),_aszErrorText[eErrorCarteIOExecute],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteJBusSlaveReadConfig"),_aszErrorText[eErrorCarteJBusSlaveReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteJBusSlavebWriteConfig"),_aszErrorText[eErrorCarteJBusSlavebWriteConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteJBusSlaveRead"),_aszErrorText[eErrorCarteJBusSlaveRead],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteJBusSlaveDispatchTrame"),_aszErrorText[eErrorCarteJBusSlaveDispatchTrame],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteMesureReadConfig"),_aszErrorText[eErrorCarteMesureReadConfig],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorCarteMesureWriteConfig"),_aszErrorText[eErrorCarteMesureWriteConfig],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorMesureStatusThreshold1"),_aszErrorText[eErrorMesureStatusThreshold1],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorMesureStatusThreshold2"),_aszErrorText[eErrorMesureStatusThreshold2],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorMesureValMax"),_aszErrorText[eErrorMesureValMax],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorMesureValMin"),_aszErrorText[eErrorMesureValMin],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgRegulControlLuggageHeatingUnattained"),_aszErrorText[eErrorPrgRegulControlLuggageHeatingUnattained],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgRegulControlHeatingTemperatureUnstable"),_aszErrorText[eErrorPrgRegulControlHeatingTemperatureUnstable],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgWaterDefaultLackOfWater"),_aszErrorText[eErrorPrgWaterDefaultLackOfWater],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgWaterDefaultDefaultMeasure"),_aszErrorText[eErrorPrgWaterDefaultDefaultMeasure],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgDefaultOpticalSetting"),_aszErrorText[eErrorPrgDefaultOpticalSetting],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgDefaultIncorrectOpticalSetting"),_aszErrorText[eErrorPrgDefaultIncorrectOpticalSetting],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgDefaultCurrentProjector"),_aszErrorText[eErrorPrgDefaultCurrentProjector],szFileMsg);
	
	
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgOpticalMeasureDefaultMeasure"),_aszErrorText[eErrorPrgOpticalMeasureDefaultMeasure],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgOpticalMeasureDefaultStability"),_aszErrorText[eErrorPrgOpticalMeasureDefaultStability],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgAbsorbanceCalculDivByZero"),_aszErrorText[eErrorPrgAbsorbanceCalculDivByZero],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgConcentrationCalculDivByZero"),_aszErrorText[eErrorPrgConcentrationCalculDivByZero],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgConcentrationCalculOutOfBound"),_aszErrorText[eErrorPrgConcentrationCalculOutOfBound],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgCalibrationCoefCalculDivByZero"),_aszErrorText[eErrorPrgCalibrationCoefCalculDivByZero],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgCalibrationCoefCalculOutOfBound"),_aszErrorText[eErrorPrgCalibrationCoefCalculOutOfBound],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgLinearisationDivByZero"),_aszErrorText[eErrorPrgLinearisationDivByZero],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgLinearisationOutOfRange"),_aszErrorText[eErrorPrgLinearisationOutOfRange],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgInverseLinDivByZero"),_aszErrorText[eErrorPrgInverseLinDivByZero],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgInverseLinOutOfRange"),_aszErrorText[eErrorPrgInverseLinOutOfRange],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgConfigInitNegativeGain"),_aszErrorText[eErrorPrgConfigInitNegativeGain],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgCalibrationCoefCalculM2DivByZero"),_aszErrorText[eErrorPrgCalibrationCoefCalculM2DivByZero],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgCalibrationCoefCalculM2OutOfGap"),_aszErrorText[eErrorPrgCalibrationCoefCalculM2OutOfGap],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgOffsetZeroCalculDivByZero"),_aszErrorText[eErrorPrgOffsetZeroCalculDivByZero],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgOffsetZeroCalculOutOfBound"),_aszErrorText[eErrorPrgOffsetZeroCalculOutOfBound],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgConfigInitNegativeProbeGain"),_aszErrorText[eErrorPrgConfigInitNegativeProbeGain],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrgHeatWaterControlDefaultHeatWater"),_aszErrorText[eErrorPrgHeatWaterControlDefaultHeatWater],szFileMsg);

	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg203"),_aszErrorText[eErrorPrg203],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg205"),_aszErrorText[eErrorPrg205],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg213"),_aszErrorText[eErrorPrg213],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg215"),_aszErrorText[eErrorPrg215],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg219"),_aszErrorText[eErrorPrg219],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg223"),_aszErrorText[eErrorPrg223],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg225"),_aszErrorText[eErrorPrg225],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg229"),_aszErrorText[eErrorPrg229],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg22D"),_aszErrorText[eErrorPrg22D],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg233"),_aszErrorText[eErrorPrg233],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg235"),_aszErrorText[eErrorPrg235],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg245"),_aszErrorText[eErrorPrg245],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg243"),_aszErrorText[eErrorPrg243],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg253"),_aszErrorText[eErrorPrg253],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg255"),_aszErrorText[eErrorPrg255],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg259"),_aszErrorText[eErrorPrg259],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg443"),_aszErrorText[eErrorPrg443],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg453"),_aszErrorText[eErrorPrg453],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg463"),_aszErrorText[eErrorPrg463],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg465"),_aszErrorText[eErrorPrg465],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg173"),_aszErrorText[eErrorPrg173],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg393"),_aszErrorText[eErrorPrg393],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg403"),_aszErrorText[eErrorPrg403],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg405"),_aszErrorText[eErrorPrg405],szFileMsg);
	bWritePrivateProfileString(_T("MSG"), _T("eErrorPrg413"),_aszErrorText[eErrorPrg413],szFileMsg);
}

static bool bInitLog()
{
	InitializeCriticalSection(&_LogCriticalSection);
	return true;
}
static bool _bInit = bInitLog();

//EX : 	TRACE_DEBUG(eTypeMsg, __FILE__,__FUNCTION__,__LINE__,"    Nb decoded line   : %d \n", 0);
void TRACE_DEBUG(int eTypeMsg,int eOrigineMsg,
	LPCTSTR szFile,			// fichier source
	LPCTSTR szFunction,			// fonction source
	int			noLigne,			// numéro de la ligne de source
	LPCTSTR	format, ... )		// format du message utilisateur
{
	TCHAR		szFileName[MAX_PATH];
	TCHAR		szTextInfo[1024];
	TCHAR		szTextDebug[1024];
	SYSTEMTIME  stTime;
    va_list		arglist;
	

	if ( ((eTypeMsg == eError) && _bShowError) ||
		 ((eTypeMsg == eWarning) && _bShowWarning) ||
		 ((eTypeMsg == eInformation) && _bShowInformation) ||
		 ((eTypeMsg == eDebug) && _bShowDebug) )
	{
		GetLocalTime(&stTime);
		_stprintf(szTextDebug, _T(" %s\r\n"),format);
    
		va_start(arglist, format);
		_vstprintf(szTextInfo, szTextDebug, arglist);
		_stprintf(szTextDebug, _T("File: %s ; Function : %s ; Line :%d LVL:%d ; ORIG:%d ; %02d:%02d:%02d:%04d ; ==> "),szFile,szFunction,noLigne, eTypeMsg,eOrigineMsg,stTime.wHour,stTime.wMinute,stTime.wSecond,stTime.wMilliseconds);
		// trace dans debugview
		if (_bDebugView) 
		{
			OutputDebugString(szTextDebug);
			OutputDebugString(szTextInfo);
		}
		if (_bTraceScreen) 
		{
			//_tprintf(szTextDebug);
			_tprintf(szTextInfo);
		}
		// trace dans le fichier de log
		if (_bLogFile)
		{
			szBuildFileName(szFileName, _T(".log"));
			bEcrireFichierLog(szTextDebug, _szLogErrorPrgFileDir, szFileName);
			bEcrireFichierLog(szTextInfo, _szLogErrorPrgFileDir, szFileName);

			//EnterCriticalSection(&_LogCriticalSection);
			//_stprintf(szLogFile, _T("%s\\%04d_%02d_%02d.log"),_szLogFileDir,stTime.wYear,stTime.wMonth,stTime.wDay);
			/*_stprintf(szLogFile, _T("%04d_%02d_%02d.log"),stTime.wYear,stTime.wMonth,stTime.wDay);
			
			//Ecrit sur le fichier de log, si le fichier existe continu a la suite, sinon, le crée
			hFile = CreateFile(szGetFullPathName(szLogFile,szText),GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				SetFilePointer(hFile,0,NULL,FILE_END);
				WriteFile(hFile,szTextDebug,_tcslen(szTextDebug)*sizeof(TCHAR),&dwNbWrite,NULL);
				WriteFile(hFile,szTextInfo,_tcslen(szTextInfo)*sizeof(TCHAR),&dwNbWrite,NULL);
				CloseHandle(hFile);
			}
			else
			{
				OutputDebugString(_T("ERREUR OUVERTURE FICHIER TRACE\r\n"));
			}
			LeaveCriticalSection(&_LogCriticalSection);*/
		}

		if (_bErrFile && (eTypeMsg == eError))
		{
			szBuildFileName(szFileName, _T(".err"));
			bEcrireFichierLog(szTextDebug, _szLogErrorPrgFileDir, szFileName);
			bEcrireFichierLog(szTextInfo, _szLogErrorPrgFileDir, szFileName);
			/*EnterCriticalSection(&_LogCriticalSection);
			//_stprintf(szLogFile,_T("%s\\%04d_%02d_%02d.err"),_szLogFileDir,stTime.wYear,stTime.wMonth,stTime.wDay);
			_stprintf(szLogFile,_T("%04d_%02d_%02d.err"),stTime.wYear,stTime.wMonth,stTime.wDay);
			hFile = CreateFile(szGetFullPathName(szLogFile,szText),GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
			if (hFile != INVALID_HANDLE_VALUE)
			{
				SetFilePointer(hFile,0,NULL,FILE_END);
				WriteFile(hFile,szTextDebug,_tcslen(szTextDebug)*sizeof(TCHAR),&dwNbWrite,NULL);
				WriteFile(hFile,szTextInfo,_tcslen(szTextInfo)*sizeof(TCHAR),&dwNbWrite,NULL);
				CloseHandle(hFile);
			}
			else
			{
				OutputDebugString(_T("ERREUR OUVERTURE FICHIER TRACE\r\n"));
			}
			LeaveCriticalSection(&_LogCriticalSection);*/
		}

		////////////////////
		COPYDATASTRUCT CopyDataStruct;

		if (_hDebugWnd)
		{
			/*CopyDataStruct.dwData = WM_TRACE;
			CopyDataStruct.cbData = (_tcslen(szTextDebug) + 1)*sizeof(TCHAR);
			CopyDataStruct.lpData = (PVOID)szTextDebug;
			*/
			::SendMessage(_hDebugWnd,WM_COPYDATA,(WPARAM)0,(LPARAM)&CopyDataStruct);
			CopyDataStruct.dwData = WM_TRACE;
			CopyDataStruct.cbData = (_tcslen(szTextInfo) + 1)*sizeof(TCHAR);
			CopyDataStruct.lpData = (PVOID)szTextInfo;

			::SendMessage(_hDebugWnd,WM_COPYDATA,(WPARAM)0,(LPARAM)&CopyDataStruct);
		}
	}


}	

void TRACE_DEBUG_LAST_ERROR(int eTypeMsg,int eOrigineMsg,DWORD dwErrNbr)
{
	LPVOID lpMsgBuf;
	FormatMessage( 
		FORMAT_MESSAGE_ALLOCATE_BUFFER | 
		FORMAT_MESSAGE_FROM_SYSTEM | 
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		GetLastError(),
		0, // Default language
		(LPTSTR) &lpMsgBuf,
		0,
		NULL 
		);
	TRACE_DEBUG(eError,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,(LPCTSTR)lpMsgBuf);
	// Free the buffer.
	LocalFree( lpMsgBuf );
}

void TRACE_DEBUG_IHM(int eTypeMsg,int eOrigineMsg, int eErrorCode, CElemInt8* argNumCurrentStream)
{
	TCHAR		szTextDebug[1024];
	SYSTEMTIME  stTime;

    if(argNumCurrentStream == 0)
    {
	    GetLocalTime(&stTime);
	    _stprintf( szTextDebug 
			     , _T(">LVL:%s ; ORIG:%s ; %04d/%02d/%02d ; %02d:%02d:%02d ; %s\r\n")
			     , aszTypeMsgTrace[eTypeMsg]
			     , aszOrigineMsgTrace[eOrigineMsg]
			     , stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour,stTime.wMinute,stTime.wSecond
			     , _aszErrorText[eErrorCode]);
    }
    else
    {
         GetLocalTime(&stTime);
	    _stprintf( szTextDebug 
            , _T(">LVL:%s ; ORIG:%s ; %04d/%02d/%02d ; %02d:%02d:%02d ; %s @%d@\r\n")
			     , aszTypeMsgTrace[eTypeMsg]
			     , aszOrigineMsgTrace[eOrigineMsg]
			     , stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour,stTime.wMinute,stTime.wSecond
			     , _aszErrorText[eErrorCode]
                 , argNumCurrentStream->ucGetVal()+1);
    }
	CListStream::m_ListMessageError.bAddAndRollText(szTextDebug);
	TRACE_DEBUG(eDebug,eOrigineMsg,_T(__FILE__),_T(__FUNCTION__),__LINE__,_aszErrorText[eErrorCode]);
}

void TRACE_LOG_MESURE(CStream* argObjVoie, CElemInt8* argNumCurrentStream, int argiMoyenne)
{
	TCHAR szMessage[500];
	TCHAR szUserMessage[500];
	TCHAR szFileName[20];
	TCHAR szFileFullPath[MAX_PATH];
	HANDLE hFile = INVALID_HANDLE_VALUE;
	SYSTEMTIME  stTime;
	GetLocalTime(&stTime);
	BOOL bWriteFile = FALSE;
	
	memset (szFileFullPath,NULL,MAX_PATH);
	int l,m,i;
	//Sortie des moyennes
	//Constitution du message de log
	l  =  _stprintf( szMessage  
				   , _T( "%04d/%02d/%02d ; %02d:%02d:%02d ; %s=%-d ")
				   , stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour
				   , stTime.wMinute,stTime.wSecond
				   , argNumCurrentStream->szGetLabel()
				   , (argNumCurrentStream->ucGetVal()+1));
	i  =  _stprintf( szUserMessage  
				   , _T( "%04d/%02d/%02d ; %02d:%02d:%02d ; %s=%-d ")
				   , stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour
				   , stTime.wMinute,stTime.wSecond
				   , argNumCurrentStream->szGetLabel()
				   , (argNumCurrentStream->ucGetVal()+1));


	for(int k=0; (k < argObjVoie->iGetNbrMesure()) && (k < NBR_MESURE_MAX); k++)
	{
		m=k;
		
		//Fait la moyenne de NB_MESURE_MOYENNEE (donc sur NB_MESURE_MOYENNEE cycle)
		if( argObjVoie->pGetAt(k)->m_iCompteurMesure < NB_MESURE_MOYENNEE)
		{
			argObjVoie->pGetAt(k)->m_SommeMesure.bSetVal(   argObjVoie->pGetAt(k)->m_SommeMesure.fGetVal()
														  + argObjVoie->pGetAt(k)->m_Val.fGetVal());
			argObjVoie->pGetAt(k)->m_iCompteurMesure++;
		}
		
		if( !(argObjVoie->pGetAt(k)->m_iCompteurMesure < NB_MESURE_MOYENNEE))
		{
			
			argObjVoie->pGetAt(k)->m_SommeMesure.bSetVal( argObjVoie->pGetAt(k)->m_SommeMesure.fGetVal()
													    / argObjVoie->pGetAt(k)->m_iCompteurMesure);
			
			l  += _stprintf( szMessage + l
				 		   , _T( "; %s=%-f; %s=%-f; %s=%-f; %s=%-f; %s=%-f; %s=%d; ")
				     	   , argObjVoie->pGetAt(k)->m_Val.szGetLabel()
						   , argObjVoie->pGetAt(k)->m_SommeMesure.fGetVal()
		    //Colorimétrie le rendre configurable pourla V3
						   , argObjVoie->pGetAt(k)->m_ZeroOpticalMeasurement.szGetLabel()
						   , argObjVoie->pGetAt(k)->m_ZeroOpticalMeasurement.fGetVal()
						   , argObjVoie->pGetAt(k)->m_OpticalMeasurement.szGetLabel()
						   , argObjVoie->pGetAt(k)->m_OpticalMeasurement.fGetVal()
			//Titrimetrie
						   , argObjVoie->pGetAt(k)->m_Delta.szGetLabel()
						   , argObjVoie->pGetAt(k)->m_Delta.fGetVal()
						   , argObjVoie->pGetAt(k)->m_AbsorbanceValue.szGetLabel()
						   , argObjVoie->pGetAt(k)->m_AbsorbanceValue.fGetVal()
						   , argObjVoie->pGetAt(k)->m_OpticalGain.szGetLabel()
						   , argObjVoie->pGetAt(k)->m_OpticalGain.nGetVal());

			i  += _stprintf( szUserMessage + i
				 		   , _T( "; %s=%-f; ")
				     	   , argObjVoie->pGetAt(k)->m_Val.szGetLabel()
						   , argObjVoie->pGetAt(k)->m_SommeMesure.fGetVal());


			argObjVoie->pGetAt(k)->m_SommeMesure.bSetVal(0);
	
			argObjVoie->pGetAt(k)->m_iCompteurMesure = 0;
		
			bWriteFile = TRUE;
	
		}

	}

	if(bWriteFile)
	{
		_stprintf( szMessage + l, _T( "\r\n"));
		_stprintf( szUserMessage + i, _T( "\r\n"));
		szBuildFileName(szFileName, _T(".txt"));
		bEcrireFichierLog(szMessage, _szLogFileDir, szFileName);
		bEcrireFichierLog(szUserMessage, _szUserLogFileDir, szFileName);
	}

	
}

void TRACE_LOG_ERROR_PRG(CStream* argObjVoie, CElemInt8* argNumCurrentStream, int argiNumMesure, int argiNumPas)
{
	TCHAR szMessage[200];
	TCHAR szFileName[20];
	
	SYSTEMTIME  stTime;
	GetLocalTime(&stTime);
	
	int l;
	l  =  _stprintf( szMessage 
				   , _T( "%04d/%02d/%02d ; %02d:%02d:%02d ; %s=%-d ")
				   , stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour
				   , stTime.wMinute,stTime.wSecond
				   , argNumCurrentStream->szGetLabel()
				   , argNumCurrentStream->ucGetVal());
	
	switch(argObjVoie->pGetAt(argiNumMesure)->m_NumProgram.ucGetVal())
	{
		//!\A gérer dynamiquement en V3 avec un fichier de conf supplémentaire pour la mapping ou pas
		//PRG_000
		case 0:
			break;
		//PRG_ATTENTE
		case 1:
			//Aucun retour
			break;
		//PRG_MARCHE_ARRET_CHAUFFE
		case 2:
			break;
		//PRG_CONTROL_REGUL_CHAUFFE
		case 3:
			 //consigne non atteinte
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgRegulControlLuggageHeatingUnattained, argNumCurrentStream);
			//mesure non stable
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgRegulControlHeatingTemperatureUnstable, argNumCurrentStream);
			break;
		//PRG_DEFAUT_EAU
		case 4:
			//Defaut d'eau
			verifierDefaut(0x01, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgWaterDefaultLackOfWater, argNumCurrentStream);
			//Defaut de mesure
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgWaterDefaultDefaultMeasure, argNumCurrentStream);

			break;
		//PRG_REGLAGE_OPTIQUE
		case 5:
			//Defaut réglage optique
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgDefaultOpticalSetting, argNumCurrentStream);
			//Defaut 
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgDefaultIncorrectOpticalSetting, argNumCurrentStream);
			//Defaut courant projecteur
			verifierDefaut(0x07, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgDefaultCurrentProjector, argNumCurrentStream);
			break;
		//PRG_MESURE_OPTIQUE
		case 6:
			//Defaut de mesure 
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgOpticalMeasureDefaultMeasure, argNumCurrentStream);
			
			//Defaut de stabilité de la mesure
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgOpticalMeasureDefaultStability, argNumCurrentStream);

			break;
		//PRG_CALCUL_ABSORBANCE
		case 7:
			//Division par zero
			verifierDefaut(0x01, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgAbsorbanceCalculDivByZero, argNumCurrentStream);
			break;
		//PRG_CALCUL_CONCENTRATION
		case 8:
			//Division par zero
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgConcentrationCalculDivByZero, argNumCurrentStream);

			//concentration hors bornes
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgConcentrationCalculOutOfBound, argNumCurrentStream);
			break;
		//PRG_CALCUL_COEF_CALIBRAGE
		case 9:
			//Division par zero
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgCalibrationCoefCalculDivByZero, argNumCurrentStream);

			//Coef d'etalonnage hors écart
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgCalibrationCoefCalculOutOfBound, argNumCurrentStream);
			break;
		//PRG_MULTIPLICATION
		case 10:
			//Aucun retour
			break;
		//PRG_LIN_AJOUT_POINTS
		case 11:
			//Aucun retour
			break;
		//PRG_LINEARISATION
		case 12:
			//Division par zero
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgLinearisationDivByZero, argNumCurrentStream);

			//valeur hors plage
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgLinearisationOutOfRange, argNumCurrentStream);
			break;
		//PRG_LINEARISATION_INVERSE
		case 13:
			//Division par zero
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgInverseLinDivByZero, argNumCurrentStream);

			//valeur hors plage
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgInverseLinOutOfRange, argNumCurrentStream);
			break;
		//PRG_INIT_CONFIG
		case 14:
			//Gain inférieur ou égal à zero
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgConfigInitNegativeGain, argNumCurrentStream);

			//Gain de la sonde de cuve inférieur ou égal à zero
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgConfigInitNegativeProbeGain, argNumCurrentStream);
			break;
		//PRG_CALCUL_COEF_CALIBRAGE_M2
		case 15:
			//Division par zero
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgCalibrationCoefCalculM2DivByZero, argNumCurrentStream);

			//Coef d'etalonnage hors écart
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgCalibrationCoefCalculM2OutOfGap, argNumCurrentStream);
			break;
		//PRG_CALCUL_OFFSET_ZERO
		case 16:
			//Division par zero
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgOffsetZeroCalculDivByZero, argNumCurrentStream);

			//Zéro hors bornes
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgOffsetZeroCalculOutOfBound, argNumCurrentStream);
			break;
		//PRG_TITRIMETRIE
		case 17:
		case 993:
			//Temps trouvé hors écart
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg173, argNumCurrentStream);
			break;
		//PRG_CONTROL_EAU_CHAUDE
		case 18:
			//eau pas à température
			verifierDefaut(0x01, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgHeatWaterControlDefaultHeatWater, argNumCurrentStream);
			break;
		//PRG_DEFAUT_EAU_MAINTENANCE
		case 19:
			//Defaut d'eau
			verifierDefaut(0x01, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgWaterDefaultLackOfWater, argNumCurrentStream);
			//Defaut de mesure
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrgWaterDefaultDefaultMeasure, argNumCurrentStream);

			break;

		//Pour les sondes rajouter les variables d'erreur ou utiliser les existantes ? 
		case 20:
			//Réglage offset sonde
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg203, argNumCurrentStream);
			//Réglage incorrect
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg205, argNumCurrentStream);
			
			break;
		case 21:
			//Mesure sonde <0
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg213, argNumCurrentStream);
			//Defaut de mesure instable
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg215, argNumCurrentStream);
			//Offset Entrant=0
			verifierDefaut(0x09, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg219, argNumCurrentStream);
			
			break;
		case 22:
			// calcul pente (Calibrage) sonde hors borne
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg225, argNumCurrentStream);
			//Defaut de calcul div / zéro
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg223, argNumCurrentStream);
			//Delta incorect
			verifierDefaut(0x09, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg229, argNumCurrentStream);
			//Delta incorect + pente mesuré incorrect
			verifierDefaut(0x0D, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg22D, argNumCurrentStream);
			break;
		case 23:
			// Calcul concentration après ajout sonde div /zéro
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg233, argNumCurrentStream);
			//Concentration ech+ajout < ajout
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg235, argNumCurrentStream);
			
			break;
		case 24:
			// coef hors borne
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg243, argNumCurrentStream);
			//division par 0
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg245, argNumCurrentStream);
			
			break;
		case 25:
			// division par 0 (delta1 =0)
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg253, argNumCurrentStream);
			//division par 0 (?)
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg255, argNumCurrentStream);
			//Calcul concentration impossible
			verifierDefaut(0x09, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg259, argNumCurrentStream);
            //Concentration négative
            verifierDefaut(0x11, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg259, argNumCurrentStream);
			
			break;
		case 38: //dosage sonde
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg393, argNumCurrentStream);
			break;
		case 39:
			// concentration mode opératoire ou volume cuve = 0
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg393, argNumCurrentStream);
			break;
		case 40:
			// Coef dénominateur formule AGV = 0
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg403, argNumCurrentStream);
			// Conc AGV = 0
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg405, argNumCurrentStream);
			
			break;
		case 41:
			// Division par zéro -  volume cuve = 0
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg413, argNumCurrentStream);
			break;
		case 44:
			// div par 0 (delta1=0)
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg443, argNumCurrentStream);	
			break;
		case 45:
			// div par 0 (Cetalon|V0|V1|V2=0)
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg453, argNumCurrentStream);	
			break;
		case 46:
			// fonctionnement mode dégradé
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg463, argNumCurrentStream);	
			// prévoir maintenance
			verifierDefaut(0x05, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg465, argNumCurrentStream);	
			break;
		case 992 : //Dosage cérium
			verifierDefaut(0x03, argObjVoie, argiNumMesure, argiNumPas, szMessage, &l, eErrorPrg393, argNumCurrentStream);
			break;
		//PRG_PAUSE
		case 998:
			//Aucun retour
			break;
		//PRG_999
		case 999:
			//aucun retour
			break;

	}

	_stprintf( szMessage + l, _T( "\r\n"));
	szBuildFileName(szFileName, _T(".txt"));
	bEcrireFichierLog(szMessage, _szLogErrorPrgFileDir, szFileName);	
		
	
	
}

void TRACE_LOG_MSG(WCHAR* argpszMessage)
{
	TCHAR szFileName[20];
	TCHAR szMessage[300];
	TCHAR szMessageScreen[300];
	
	SYSTEMTIME  stTime;
	GetLocalTime(&stTime);
	
	int l;
	l  =  _stprintf( szMessage 
				   , _T( "%04d/%02d/%02d ; %02d:%02d:%02d ; %s \r\n")
				   , stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour
				   , stTime.wMinute,stTime.wSecond
				   , argpszMessage);
	_stprintf( szMessageScreen 
				   , _T( "%s \r\n")
				   , argpszMessage);
	szBuildFileName(szFileName, _T(".txt"));
	bEcrireFichierLog(szMessage, _szLogFileDir, szFileName);
	_tprintf(szMessageScreen);
	OutputDebugString(szMessageScreen);
}

//affichage du temps en millisonde
void TRACE_DEBUG_MSG_TIME(WCHAR* argpszMessage, int iID)
{
	TCHAR szFileName[20];
	TCHAR szMessage[300];
	TCHAR szMessageScreen[300];

	
	SYSTEMTIME  stTime;
	GetLocalTime(&stTime);
	int dwTick = GetTickCount();
	int l;
	l  =  _stprintf( szMessage 
		, _T( "%04d/%02d/%02d ; %02d:%02d:%02d:%04d; ID:%d ; TickCount;%d %s \r\n")
				   , stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour
				   , stTime.wMinute,stTime.wSecond,stTime.wMilliseconds
				   , iID, dwTick
				   , argpszMessage);
	OutputDebugString(szMessage);
}

void verifierDefaut(BYTE argcErrorToCheck, CStream* argObjVoie, int argiNumMesure, int argiNumPas, WCHAR* argpszMessage, int* argpIndexMessage, int argeError, CElemInt8* argNumCurrentStream)
{
	if(    (argObjVoie->pGetAt(argiNumMesure)->m_StatusFailure.ucGetVal() | argcErrorToCheck) 

				== argObjVoie->pGetAt(argiNumMesure)->m_StatusFailure.ucGetVal())
	{
		*argpIndexMessage  += _stprintf( argpszMessage + *argpIndexMessage
		 							   , _T( "; %s; Step %d; %s ")
		     						   , argObjVoie->pGetAt(argiNumMesure)->m_Val.szGetLabel() //mesure concerné
									   , argiNumPas
									   , _aszErrorText[argeError]);
		TRACE_DEBUG_IHM(eError,eMesure,argeError, argNumCurrentStream);
	}
}


//Ecrit un message dans un fichier de log en fonction d'un chemin.
//La méthode vérifie si le chemin spécifier existe. Si il n'existe pas le chemin est créé
//ainsi que le fichier où écrire le message
BOOL bEcrireFichierLog(WCHAR* argpszMessage, WCHAR* argpszFullPath, WCHAR* argpszFileName)
{

	TCHAR szTempPath[MAX_PATH];
	BOOL bWriteFile = FALSE;
	memset (szTempPath,NULL,MAX_PATH);
	DWORD dwNbWrite;
	HANDLE hFile = INVALID_HANDLE_VALUE;

	SYSTEMTIME  stTime;
	GetLocalTime(&stTime);

	BOOL bFinVerif=FALSE;
	int j = 0; //position du caractère dans argpszFullPath

	EnterCriticalSection(&_LogCriticalSection);

	while(	   !bFinVerif
			&& j < MAX_PATH
			&& argpszFullPath[j] != NULL )
	{
		do
		{
			szTempPath[j] = argpszFullPath[j];
			j++;

		}while(    j < MAX_PATH
				&& argpszFullPath[j] != NULL 
				&& argpszFullPath[j] != argpszFullPath[0] );

		//Crée le dossier si il n'éxiste pas
		//Si on ne peut pas créer le fichier, on sort de la procédure
		if(    (!CreateDirectory( szTempPath, NULL))
			&& (!(GetLastError() == ERROR_ALREADY_EXISTS)))
		{
			OutputDebugString(_T("ERREUR CREATION DOSSIER \r\n"));
			return false;
		}
		
		if(	!(j < MAX_PATH && argpszFullPath[j] != NULL))
		{
			bFinVerif = TRUE;
		}
		else
		{
			szTempPath[j] = argpszFullPath[j];
			j++;
		}

	}

	wcscat(szTempPath, _T("\\"));
	wcscat(szTempPath, argpszFileName);

	

	hFile = CreateFile( szTempPath
					  , GENERIC_READ|GENERIC_WRITE
				      , 0
					  , NULL
					  , OPEN_ALWAYS
					  , FILE_ATTRIBUTE_NORMAL
					  , NULL);

	if (hFile != INVALID_HANDLE_VALUE)
	{
		SetFilePointer(hFile,0,NULL,FILE_END);

		WriteFile(hFile,argpszMessage,_tcslen(argpszMessage)*sizeof(TCHAR),&dwNbWrite,NULL);
		CloseHandle(hFile);
	}
	else
	{
		OutputDebugString(_T("ERREUR OUVERTURE FICHIER TRACE\r\n"));
	}

	bWriteFile = FALSE;
	LeaveCriticalSection(&_LogCriticalSection);

	return true;
}

void szBuildFileName(WCHAR* argszFileName, WCHAR* argszExt)
{
	SYSTEMTIME  stTime;
	GetLocalTime(&stTime);

	_stprintf( argszFileName
			 , _T( "%04d_%02d_%02d")
			 , stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour);
	wcscat(argszFileName, argszExt);
}
