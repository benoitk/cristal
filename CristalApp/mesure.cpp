#include "stdafx.h"
#include "network.h"




/*(@!*****************************************************************************************
* Nom     : CMesure
* Role    : definition d'une mesure
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
CMesure::CMesure(BYTE ucNumVoie,BYTE ucNumMesure):CElemBase(),m_ListCoeffLinear(NBR_COEFF_LINEAR),m_ListMesureMoy(NBR_MESURE_MOY),m_ListRealtimeData(NBR_REALTIME_DATA)
{
	m_iType = MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_MESURE,0xFF);
	SetLabel(_T("CMesure"));
	SetElemName(QString("CMesure"));
	// mesure
	m_Val.SetLabel(_T("m_Val"));
	m_Val.SetElemName(QString("m_Val"));
	m_Val.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_VAL));
	// val Min
	m_ValMin.SetLabel(_T("m_ValMin"));
	m_ValMin.SetElemName(QString("m_ValMin"));
	m_ValMin.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_VALMIN));
	// val max
	m_ValMax.SetLabel(_T("m_ValMax"));
	m_ValMax.SetElemName(QString("m_ValMax"));
	m_ValMax.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_VALMAX));
	// status
	m_StatusFailure.SetLabel(_T("m_StatusFailure"));
	m_StatusFailure.SetElemName(QString("m_StatusFailure"));
	m_StatusFailure.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_STATUS_FAILURE));
	// seuil1
	m_Threshold1.SetLabel(_T("m_Threshold1"));
	m_Threshold1.SetElemName(QString("m_Threshold1"));
	m_Threshold1.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_THRESHOLD1));
	// seuil2
	m_Threshold2.SetLabel(_T("m_Threshold2"));
	m_Threshold2.SetElemName(QString("m_Threshold2"));
	m_Threshold2.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_THRESHOLD2));
	// status seuil1
	m_StatusThreshold1.SetLabel(_T("m_StatusThreshold1"));
	m_StatusThreshold1.SetElemName(QString("m_StatusThreshold1"));
	m_StatusThreshold1.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1));
	// status seuil2
	m_StatusThreshold2.SetLabel(_T("m_StatusThreshold2"));
	m_StatusThreshold2.SetElemName(QString("m_StatusThreshold2"));
	m_StatusThreshold2.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2));
	// zero 4/20
	m_AnalogZero.SetLabel(_T("m_AnalogZero"));
	m_AnalogZero.SetElemName(QString("m_AnalogZero"));
	m_AnalogZero.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_ANALOG_ZERO));
	// max 4/20
	m_AnalogPlage.SetLabel(_T("m_AnalogPlage"));
	m_AnalogPlage.SetElemName(QString("m_AnalogPlage"));
	m_AnalogPlage.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_ANALOG_PLAGE));
	// Coeff de calibration
	m_CalibCoeff.SetLabel(_T("m_CalibCoeff"));
	m_CalibCoeff.SetElemName(QString("m_CalibCoeff"));
	m_CalibCoeff.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_COEFF));

	// Coeff de zero water
	m_CalibZeroWater.SetLabel(_T("m_CalibZeroWater"));
	m_CalibZeroWater.SetElemName(QString("m_CalibZeroWater"));
	m_CalibZeroWater.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_ZERO_WATER));

	// Coeff de zero air
	m_CalibZeroAir.SetLabel(_T("m_CalibZeroAir"));
	m_CalibZeroAir.SetElemName(QString("m_CalibZeroAir"));
	m_CalibZeroAir.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_ZERO_AIR));

	// status calib coeff
	m_CalibStatusCoeff.SetLabel(_T("m_CalibStatusCoeff"));
	m_CalibStatusCoeff.SetElemName(QString("m_CalibStatusCoeff"));
	m_CalibStatusCoeff.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF));

	// status calib zero
	m_CalibStatusZero.SetLabel(_T("m_CalibStatusZero"));
	m_CalibStatusZero.SetElemName(QString("m_CalibStatusZero"));
	m_CalibStatusZero.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO	));
	
	//type de sueils 
	m_SettingThreshold.SetLabel(_T("m_SettingThreshold"));
	m_SettingThreshold.SetElemName(QString("m_SettingThreshold"));
	m_SettingThreshold.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_SETTING_THRESHOLD	));
	
	// liste des coeffs
	m_ListCoeffLinear.SetLabel(_T("m_ListCoeffLinear"));
	m_ListCoeffLinear.SetElemName(QString("m_ListCoeffLinear"));
	m_ListCoeffLinear.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_LIST,eID_MESURE_LIST_COEFF_LINEAR));
	// liste des moyennes
	m_ListMesureMoy.SetLabel(_T("m_ListMesureMoy"));
	m_ListMesureMoy.SetElemName(QString("m_ListMesureMoy"));
	m_ListMesureMoy.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_LIST,eID_MESURE_LIST_MOYENNE));
	// liste des datas temps-reels
	m_ListRealtimeData.SetLabel(_T("m_ListRealtimeData"));
	m_ListRealtimeData.SetElemName(QString("m_ListRealtimeData"));
	m_ListRealtimeData.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_LIST,eID_MESURE_LIST_REALTIMEDATA));

	// valeur mesure pour Jbus Slave
	m_ValJbusSlave.SetLabel(_T("m_ValJbusSlave"));
	m_ValJbusSlave.SetElemName(QString("m_ValJbusSlave"));
	m_ValJbusSlave.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE));
	// coeff multiplicateur valeur mesure pour Jbus Slave
	m_CoeffValJbusSlave.SetLabel(_T("m_CoeffValJbusSlave"));
	m_CoeffValJbusSlave.SetElemName(QString("m_CoeffValJbusSlave"));
	m_CoeffValJbusSlave.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_COEFF_VAL_JBUS_SLAVE));
	// valeur mesure pour carte IO
	m_ValAna.SetLabel(_T("m_ValAna"));
	m_ValAna.SetElemName(QString("m_ValAna"));
	m_ValAna.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT16,eID_MESURE_VAL_IO));
	// valeur conversisseur max pour carte IO
	m_ValMaxConvertisseur.SetLabel(_T("m_ValMaxConvertisseur"));
	m_ValMaxConvertisseur.SetElemName(QString("m_ValMaxConvertisseur"));
	m_ValMaxConvertisseur.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT16,eID_MESURE_VAL_IO_MAX_DAC));
	// valeur conversisseur min pour carte IO
	m_ValMinConvertisseur.SetLabel(_T("m_ValMinConvertisseur"));
	m_ValMinConvertisseur.SetElemName(QString("m_ValMinConvertisseur"));
	m_ValMinConvertisseur.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT16,eID_MESURE_VAL_IO_MIN_DAC));
	//Valeur absorbance pur Jbus Slave
	
	// Gain optique
	m_OpticalGain.SetLabel(_T("m_OpticalGain"));
	m_OpticalGain.SetElemName(QString("m_OpticalGain"));
	m_OpticalGain.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT16,eID_MESURE_OPTICAL_GAIN));
	// valeur etalon
	m_ZeroOpticalMeasurement.SetLabel(_T("m_ZeroOpticalMeasurement"));
	m_ZeroOpticalMeasurement.SetElemName(QString("m_ZeroOpticalMeasurement"));
	m_ZeroOpticalMeasurement.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_ZERO_OPTICAL_MEASUREMENT));
	// mesure absorbance
	m_AbsorbanceValue.SetLabel(_T("m_AbsorbanceValue"));
	m_AbsorbanceValue.SetElemName(QString("m_AbsorbanceValue"));
	m_AbsorbanceValue.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_ABSORBANCE_VALUE));
	// valeur étalon avant
	m_StandardValueBefore.SetLabel(_T("m_StandardValueBefore"));
	m_StandardValueBefore.SetElemName(QString("m_StandardValueBefore"));
	m_StandardValueBefore.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_STANDARD_VALUE_BEFORE));
	// valeur étalon après
	m_StandardValueAfter.SetLabel(_T("m_StandardValueAfter"));
	m_StandardValueAfter.SetElemName(QString("m_StandardValueAfter"));
	m_StandardValueAfter.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_STANDARD_VALUE_AFTER));
	// ancien coeff de calib
	m_CalibCoeffNew.SetLabel(_T("m_CalibCoeffNew"));
	m_CalibCoeffNew.SetElemName(QString("m_CalibCoeffNew"));
	m_CalibCoeffNew.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_COEFF_NEW));
	// mesure optique
	m_OpticalMeasurement.SetLabel(_T("m_OpticalMeasurement"));
	m_OpticalMeasurement.SetElemName(QString("m_OpticalMeasurement"));
	m_OpticalMeasurement.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_OPTICAL_MEASUREMENT));
	// absorbance de reference 
	m_AbsorbanceReference.SetLabel(_T("m_AbsorbanceReference"));
	m_AbsorbanceReference.SetElemName(QString("m_AbsorbanceReference"));
	m_AbsorbanceReference.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_ABSORBANCE_REFERENCE));
	// concentration brut 
	m_RawConcentration.SetLabel(_T("m_RawConcentration"));
	m_RawConcentration.SetElemName(QString("m_RawConcentration"));
	m_RawConcentration.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_RAW_CONCENTRATION));
	
	// Absorbance corrigé 
	m_CorrectedAbsorbance.SetLabel(_T("m_CorrectedAbsorbance"));
	m_CorrectedAbsorbance.SetElemName(QString("m_CorrectedAbsorbance"));
	m_CorrectedAbsorbance.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_CORRECTED_ABSORBANCE));
	//Absorbance réel
	m_RealAbsorbance.SetLabel(_T("m_RealAbsorbance"));
	m_RealAbsorbance.SetElemName(QString("m_RealAbsorbance"));
	m_RealAbsorbance.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_REAL_ABSORBANCE));
	//Delta entre deux mesures 
	m_Delta.SetLabel(_T("m_Delta"));
	m_Delta.SetElemName(QString("m_Delta"));
	m_Delta.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_DELTA));
	m_CalibZeroWaterNew.SetLabel(_T("m_CalibZeroWaterNew"));
	m_CalibZeroWaterNew.SetElemName(QString("m_CalibZeroWaterNew"));
	m_CalibZeroWaterNew.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_ZERO_WATER_NEW));
    m_NumProgram.SetLabel(_T("m_NumProgram"));;
    m_NumProgram.SetElemName(QString("m_NumProgram"));;
	m_NumProgram.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_NUM_PROGRAM));

	m_AirSetPointAdjustement.SetLabel(_T("m_AirSetPointAdjustement"));
	m_AirSetPointAdjustement.SetElemName(QString("m_AirSetPointAdjustement"));
	m_AirSetPointAdjustement.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT16,eID_MESURE_AIR_SETPOINT_ADJUSTEMENT));
	m_AirRefMeasureRedrSync.SetLabel(_T("m_AirRefMeasureRedrSync"));
	m_AirRefMeasureRedrSync.SetElemName(QString("m_AirRefMeasureRedrSync"));
	m_AirRefMeasureRedrSync.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_AIR_REF_MEASURE_REDRSYNC));
	m_AirWaterFlag.SetLabel(_T("m_AirWaterFlag"));
	m_AirWaterFlag.SetElemName(QString("m_AirWaterFlag"));
	m_AirWaterFlag.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_AIR_WATER_FLAG));
	m_RefBaseline.SetLabel(_T("m_RefBaseline"));
	m_RefBaseline.SetElemName(QString("m_RefBaseline"));
	m_RefBaseline.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_REF_BASELINE));
	m_Water90.SetLabel(_T("m_Water90"));
	m_Water90.SetElemName(QString("m_Water90"));
	m_Water90.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_WATER_90));
	m_Turbidity90.SetLabel(_T("m_Turbidity90"));
	m_Turbidity90.SetElemName(QString("m_Turbidity90"));
	m_Turbidity90.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_TURBIDITY_90));
	m_TurbidityFinal.SetLabel(_T("m_TurbidityFinal"));
	m_TurbidityFinal.SetElemName(QString("m_TurbidityFinal"));
	m_TurbidityFinal.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_TURBIDITY_FINAL));
	m_TurbidityCoef.SetLabel(_T("m_TurbidityCoef"));
	m_TurbidityCoef.SetElemName(QString("m_TurbidityCoef"));
	m_TurbidityCoef.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_TURBIDITY_COEF));
	m_TurbidityStandard.SetLabel(_T("m_TurbidityStandard"));
	m_TurbidityStandard.SetElemName(QString("m_TurbidityStandard"));
	m_TurbidityStandard.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_TURBIDITY_STANDARD));
	m_AirOpticalGain.SetLabel(_T("m_AirOpticalGain"));
	m_AirOpticalGain.SetElemName(QString("m_AirOpticalGain"));
	m_AirOpticalGain.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_AIR_OPTICAL_GAIN));
	m_AirRedrSync.SetLabel(_T("m_AirRedrSync"));
	m_AirRedrSync.SetElemName(QString("m_AirRedrSync"));
	m_AirRedrSync.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_AIR_REDRSYNC));
	m_AbsorbanceTurbidity180.SetLabel(_T("m_AbsorbanceTurbidity180"));
	m_AbsorbanceTurbidity180.SetElemName(QString("m_AbsorbanceTurbidity180"));
	m_AbsorbanceTurbidity180.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_ABSORBANCE_TURBIDITY_180));
	m_AbsorbanceCorrected.SetLabel(_T("m_AbsorbanceCorrected"));
	m_AbsorbanceCorrected.SetElemName(QString("m_AbsorbanceCorrected"));
	m_AbsorbanceCorrected.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_ABSORBANCE_CORRECTED));
	m_OpticalGain90.SetLabel(_T("m_OpticalGain90"));
	m_OpticalGain90.SetElemName(QString("m_OpticalGain90"));
	m_OpticalGain90.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT16,eID_MESURE_OPTICAL_GAIN_90));
	m_CourantLedColo.SetLabel(_T("m_CourantLedColo"));
	m_CourantLedColo.SetElemName(QString("m_CourantLedColo"));
	m_CourantLedColo.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_COURANT_LED_COLO));
	m_MeasureSetByLed.SetLabel(_T("m_MeasureSetByLed"));
	m_MeasureSetByLed.SetElemName(QString("m_MeasureSetByLed"));
	m_MeasureSetByLed.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_MEASURE_BY_LED));
	m_Turbidity.SetLabel(_T("m_Turbidity"));
	m_Turbidity.SetElemName(QString("m_Turbidity"));
	m_Turbidity.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_TURBIDITY));
	m_Temperature.SetLabel(_T("m_Temperature"));
	m_Temperature.SetElemName(QString("m_Temperature"));
	m_Temperature.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_TEMPERATURE));
	m_ZeroStandard.SetLabel(_T("m_ZeroStandard"));
	m_ZeroStandard.SetElemName(QString("m_ZeroStandard"));
	m_ZeroStandard.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_ZERO_STANDARD));
	m_CoefDilution.SetLabel(_T("m_CoefDilution"));
	m_CoefDilution.SetElemName(QString("m_CoefDilution"));
	m_CoefDilution.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_COEF_DILUTION));
	m_CoefAjustement.SetLabel(_T("m_CoefAjustement"));
	m_CoefAjustement.SetElemName(QString("m_CoefAjustement"));
	m_CoefAjustement.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_FLOAT,eID_MESURE_COEF_AJUSTEMENT));
	m_StatusSonde.SetLabel(_T("m_StatusSonde"));
	m_StatusSonde.SetElemName(QString("m_StatusSonde"));
	m_StatusSonde.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_LISTSTREAM_STATUS_SONDE));
	m_StatusConcentration.SetLabel(_T("m_StatusConcentration"));
	m_StatusConcentration.SetElemName(QString("m_StatusConcentration"));
	m_StatusConcentration.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_LISTSTREAM_STATUS_CONCENTRATION));
	m_AlarmDelta.SetLabel(_T("m_AlarmDelta"));
	m_AlarmDelta.SetElemName(QString("m_AlarmDelta"));
	m_AlarmDelta.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_ALARM_DELTA));
    m_AlarmDelta2.SetLabel(_T("m_AlarmDelta2"));
	m_AlarmDelta2.SetElemName(QString("m_AlarmDelta2"));
	m_AlarmDelta2.SetType(MAKE_ID(ucNumVoie,ucNumMesure,eTYPE_INT8,eID_MESURE_ALARM_DELTA2));


	//Init des variables non présente dans le fichier de conf
	m_SommeMesure.bSetVal(0);
	m_iCompteurMesure = 0;
}

CMesure::CMesure():CElemBase(),m_ListCoeffLinear(NBR_COEFF_LINEAR),m_ListMesureMoy(NBR_MESURE_MOY),m_ListRealtimeData(NBR_REALTIME_DATA)
{
}


CMesure::~CMesure()
{
	m_ListCoeffLinear.RemoveAll();
	m_ListMesureMoy.RemoveAll();
	m_ListRealtimeData.RemoveAll();
}

BOOL CMesure::bSerialize(CContext &Context)
{
	BOOL bReturn = TRUE;

	bReturn = CElemBase::bSerialize(Context);
	if (bReturn) bReturn = m_Val.bSerialize(Context);
	if (bReturn) bReturn = m_ValMax.bSerialize(Context);
	if (bReturn) bReturn = m_ValMin.bSerialize(Context);
	if (bReturn) bReturn = m_StatusFailure.bSerialize(Context);
	if (bReturn) bReturn = m_Threshold1.bSerialize(Context);
	if (bReturn) bReturn = m_Threshold2.bSerialize(Context);
	if (bReturn) bReturn = m_StatusThreshold1.bSerialize(Context);
	if (bReturn) bReturn = m_StatusThreshold2.bSerialize(Context);
	if (bReturn) bReturn = m_AnalogZero.bSerialize(Context);
	if (bReturn) bReturn = m_AnalogPlage.bSerialize(Context);
	if (bReturn) bReturn = m_CalibCoeff.bSerialize(Context);
	if (bReturn) bReturn = m_CalibZeroWater.bSerialize(Context);
	if (bReturn) bReturn = m_CalibZeroAir.bSerialize(Context);
	if (bReturn) bReturn = m_CalibStatusCoeff.bSerialize(Context);
	if (bReturn) bReturn = m_CalibStatusZero.bSerialize(Context); 
	if (bReturn) bReturn = m_SettingThreshold.bSerialize(Context);

	if (bReturn) bReturn = m_ListCoeffLinear.bSerialize(Context);
	if (bReturn) bReturn = m_ListMesureMoy.bSerialize(Context);
	if (bReturn) bReturn = m_ListRealtimeData.bSerialize(Context);
	if (bReturn) bReturn = m_ValJbusSlave.bSerialize(Context);
	if (bReturn) bReturn = m_CoeffValJbusSlave.bSerialize(Context);
	if (bReturn) bReturn = m_ValAna.bSerialize(Context);
	if (bReturn) bReturn = m_ValMaxConvertisseur.bSerialize(Context);
	if (bReturn) bReturn = m_ValMinConvertisseur.bSerialize(Context);

	// Gain optique
	if (bReturn) bReturn = m_OpticalGain.bSerialize(Context);
	// valeur etalon
	if (bReturn) bReturn = m_ZeroOpticalMeasurement.bSerialize(Context);
	// mesure absorbance
	if (bReturn) bReturn = m_AbsorbanceValue.bSerialize(Context);
	// valeur étalon avant
	if (bReturn) bReturn = m_StandardValueBefore.bSerialize(Context);
	// valeur étalon après
	if (bReturn) bReturn = m_StandardValueAfter.bSerialize(Context);
	// ancien coeff de calib
	if (bReturn) bReturn = m_CalibCoeffNew.bSerialize(Context);
	// mesure optique
	if (bReturn) bReturn = m_OpticalMeasurement.bSerialize(Context);
	// absorbance de reference 
	if (bReturn) bReturn = m_AbsorbanceReference.bSerialize(Context);
	// concentration brut 
	if (bReturn) bReturn = m_RawConcentration.bSerialize(Context);
	
	// Absorbance corrigé
	if (bReturn) bReturn = m_CorrectedAbsorbance.bSerialize(Context);
	//Absorbance réel 
	if (bReturn) bReturn = m_RealAbsorbance.bSerialize(Context);
	//Delta entre deux mesures
	if (bReturn) bReturn = m_Delta.bSerialize(Context);
	if (bReturn) bReturn = m_CalibZeroWaterNew.bSerialize(Context);
	if (bReturn) bReturn = m_NumProgram.bSerialize(Context);
	if (bReturn) bReturn = m_AirSetPointAdjustement.bSerialize(Context);
	if (bReturn) bReturn = m_AirRefMeasureRedrSync.bSerialize(Context);
	if (bReturn) bReturn = m_AirWaterFlag.bSerialize(Context);
	if (bReturn) bReturn = m_RefBaseline.bSerialize(Context);
	if (bReturn) bReturn = m_Water90.bSerialize(Context);
	if (bReturn) bReturn = m_Turbidity90.bSerialize(Context);
	if (bReturn) bReturn = m_TurbidityFinal.bSerialize(Context);
	if (bReturn) bReturn = m_TurbidityCoef.bSerialize(Context);
	if (bReturn) bReturn = m_TurbidityStandard.bSerialize(Context);
	if (bReturn) bReturn = m_AirOpticalGain.bSerialize(Context);
	if (bReturn) bReturn = m_AirRedrSync.bSerialize(Context);
	if (bReturn) bReturn = m_AbsorbanceTurbidity180.bSerialize(Context);
	if (bReturn) bReturn = m_AbsorbanceCorrected.bSerialize(Context);
	if (bReturn) bReturn = m_OpticalGain90.bSerialize(Context);
	if (bReturn) bReturn = m_CourantLedColo.bSerialize(Context);
	if (bReturn) bReturn = m_MeasureSetByLed.bSerialize(Context);
	if (bReturn) bReturn = m_Turbidity.bSerialize(Context);
	if (bReturn) bReturn = m_Temperature.bSerialize(Context);
	if (bReturn) bReturn = m_ZeroStandard.bSerialize(Context);
	if (bReturn) bReturn = m_CoefDilution.bSerialize(Context);
	if (bReturn) bReturn = m_CoefAjustement.bSerialize(Context);
	if (bReturn) bReturn = m_StatusSonde.bSerialize(Context);
	if (bReturn) bReturn = m_StatusConcentration.bSerialize(Context);
	if (bReturn) bReturn = m_AlarmDelta.bSerialize(Context);
	if (bReturn) bReturn = m_AlarmDelta2.bSerialize(Context);

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		m_StatusFailure.bSetVal(1);
	}
	return bReturn;
}

int CMesure::iGetStreamSize(CContext &Context)
{
	int iSize = 0;

	iSize = CElemBase::iGetStreamSize(Context);
	iSize += m_Val.iGetStreamSize(Context);
	iSize += m_ValMax.iGetStreamSize(Context);
	iSize += m_ValMin.iGetStreamSize(Context);
	iSize += m_StatusFailure.iGetStreamSize(Context);
	iSize += m_Threshold1.iGetStreamSize(Context);
	iSize += m_Threshold2.iGetStreamSize(Context);
	iSize += m_StatusThreshold1.iGetStreamSize(Context);
	iSize += m_StatusThreshold2.iGetStreamSize(Context);
	iSize += m_AnalogZero.iGetStreamSize(Context);
	iSize += m_AnalogPlage.iGetStreamSize(Context);
	iSize += m_CalibCoeff.iGetStreamSize(Context);
	iSize += m_CalibZeroWater.iGetStreamSize(Context);
	iSize += m_CalibZeroAir.iGetStreamSize(Context);
	iSize += m_CalibStatusCoeff.iGetStreamSize(Context);
	iSize += m_CalibStatusZero.iGetStreamSize(Context);
	iSize += m_SettingThreshold.iGetStreamSize(Context);

	iSize += m_ListCoeffLinear.iGetStreamSize(Context);
	iSize += m_ListMesureMoy.iGetStreamSize(Context);
	iSize += m_ListRealtimeData.iGetStreamSize(Context);
	
	iSize += m_ValJbusSlave.iGetStreamSize(Context);
	iSize += m_CoeffValJbusSlave.iGetStreamSize(Context);
	iSize += m_ValAna.iGetStreamSize(Context);
	iSize += m_ValMaxConvertisseur.iGetStreamSize(Context);
	iSize += m_ValMinConvertisseur.iGetStreamSize(Context);

	// Gain optique
	iSize += m_OpticalGain.iGetStreamSize(Context);
	// valeur etalon
	iSize += m_ZeroOpticalMeasurement.iGetStreamSize(Context);
	// mesure absorbance
	iSize += m_AbsorbanceValue.iGetStreamSize(Context);
	// valeur étalon avant
	iSize += m_StandardValueBefore.iGetStreamSize(Context);
	// valeur étalon après
	iSize += m_StandardValueAfter.iGetStreamSize(Context);
	// ancien coeff de calib
	iSize += m_CalibCoeffNew.iGetStreamSize(Context);
	// mesure optique
	iSize += m_OpticalMeasurement.iGetStreamSize(Context);
	// absorbance de reference 
	iSize += m_AbsorbanceReference.iGetStreamSize(Context);
	// concentration brut 
	iSize += m_RawConcentration.iGetStreamSize(Context);
	// Absorbance corrigé
	iSize += m_CorrectedAbsorbance.iGetStreamSize(Context);
	//Absorbance réel 
	iSize += m_RealAbsorbance.iGetStreamSize(Context);
	//Delta entre deux mesures 
	iSize += m_Delta.iGetStreamSize(Context);
	iSize += m_CalibZeroWaterNew.iGetStreamSize(Context);
	iSize += m_NumProgram.iGetStreamSize(Context);
	iSize += m_AirSetPointAdjustement.iGetStreamSize(Context);
	iSize += m_AirRefMeasureRedrSync.iGetStreamSize(Context);
	iSize += m_AirWaterFlag.iGetStreamSize(Context);
	iSize += m_RefBaseline.iGetStreamSize(Context);
	iSize += m_Water90.iGetStreamSize(Context);
	iSize += m_Turbidity90.iGetStreamSize(Context);
	iSize += m_TurbidityFinal.iGetStreamSize(Context);
	iSize += m_TurbidityCoef.iGetStreamSize(Context);
	iSize += m_TurbidityStandard.iGetStreamSize(Context);
	iSize += m_AirOpticalGain.iGetStreamSize(Context);
	iSize += m_AirRedrSync.iGetStreamSize(Context);
	iSize += m_AbsorbanceTurbidity180.iGetStreamSize(Context);
	iSize += m_AbsorbanceCorrected.iGetStreamSize(Context);
	iSize += m_OpticalGain90.iGetStreamSize(Context);
	iSize += m_CourantLedColo.iGetStreamSize(Context);
	iSize += m_MeasureSetByLed.iGetStreamSize(Context);
	iSize += m_Turbidity.iGetStreamSize(Context);
	iSize += m_Temperature.iGetStreamSize(Context);
	iSize += m_ZeroStandard.iGetStreamSize(Context);
	iSize += m_CoefDilution.iGetStreamSize(Context);
	iSize += m_CoefAjustement.iGetStreamSize(Context);
	iSize += m_StatusSonde.iGetStreamSize(Context);
	iSize += m_StatusConcentration.iGetStreamSize(Context);
	iSize += m_AlarmDelta.iGetStreamSize(Context);
	iSize += m_AlarmDelta2.iGetStreamSize(Context);

	return iSize;
}

BOOL CMesure::bReadConfig(int iNumStream, int iNumMesure, LPCTSTR pszFileName)
{
	BOOL bReturn = TRUE;
	TCHAR szRub[MAX_PATH];
	TCHAR szText[MAX_PATH];
	TCHAR szText2[MAX_PATH];
	int i;
	TCHAR szSeps[]   = _T("|");

	_stprintf(szRub,_T("CStream%d_CMesure%d"),iNumStream, iNumMesure);
	// StatusFailure
	_stprintf(szText2,_T("0x%08x|m_StatusFailure|0.|BOOL|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT8,eID_MESURE_STATUS_FAILURE),m_StatusFailure.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StatusFailure"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StatusFailure.bSetConfig(szText);
	m_StatusFailure.bSetVal(0);
	// mesure
	_stprintf(szText2,_T("0x%08x|Valeur mesure|0.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_VAL),m_Val.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Val"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Val.bSetConfig(szText);
	// valeur MIN MAX
	_stprintf(szText2,_T("0x%08x|ValMin|0.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_VALMIN),m_ValMin.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ValMin"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ValMin.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|ValMax|0.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_VALMAX),m_ValMax.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ValMax"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ValMax.bSetConfig(szText);
	// seuil1
	_stprintf(szText2,_T("0x%08x|Threshold1|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_THRESHOLD1),m_Threshold1.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Threshold1"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Threshold1.bSetConfig(szText);
	// seuil2
	_stprintf(szText2,_T("0x%08x|Threshold2|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_THRESHOLD2),m_Threshold2.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Threshold2"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Threshold2.bSetConfig(szText);
	// status seuil1
	_stprintf(szText2,_T("0x%08x|StatusThreshold1|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD1),m_StatusThreshold1.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StatusThreshold1"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StatusThreshold1.bSetConfig(szText);
	m_StatusThreshold1.bSetVal(0);
	// status seuil2
	_stprintf(szText2,_T("0x%08x|StatusThreshold2|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT8,eID_MESURE_STATUS_THRESHOLD2),m_StatusThreshold2.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StatusThreshold2"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StatusThreshold2.bSetConfig(szText);
	m_StatusThreshold2.bSetVal(0);
	// 4/20
	_stprintf(szText2,_T("0x%08x|AnalogZero|0.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_ANALOG_ZERO),m_AnalogZero.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AnalogZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AnalogZero.bSetConfig(szText);
	_stprintf(szText2,_T("0x%08x|AnalogMax|0.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_ANALOG_PLAGE),m_AnalogPlage.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AnalogPlage"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AnalogPlage.bSetConfig(szText);
	// Coeff de calibration
	_stprintf(szText2,_T("0x%08x|CalibCoeff|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_COEFF),m_CalibCoeff.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CalibCoeff"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CalibCoeff.bSetConfig(szText);
	// calib zero water
	_stprintf(szText2,_T("0x%08x|CalibZeroWater|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_ZERO_WATER),m_CalibZeroWater.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CalibZeroWater"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CalibZeroWater.bSetConfig(szText);
	// calib zero air
	_stprintf(szText2,_T("0x%08x|CalibZeroAir|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_ZERO_AIR),m_CalibZeroAir.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CalibZeroAir"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CalibZeroAir.bSetConfig(szText);
	// status calib coeff
	_stprintf(szText2,_T("0x%08x|CalibStatusCoeff|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT8,eID_MESURE_CALIB_STATUS_COEFF),m_CalibStatusCoeff.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CalibStatusCoeff"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CalibStatusCoeff.bSetConfig(szText);
	// status calib zero
	_stprintf(szText2,_T("0x%08x|CalibStatusZero|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT8,eID_MESURE_CALIB_STATUS_ZERO),m_CalibStatusZero.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CalibStatusZero"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CalibStatusZero.bSetConfig(szText);
	//Type de sueils (0=bas/bas 1=bas/haut 2=haut/haut)
	_stprintf(szText2,_T("0x%08x|SettingThreshold|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT8,eID_MESURE_SETTING_THRESHOLD),m_SettingThreshold.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_SettingThreshold"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_SettingThreshold.bSetConfig(szText);

	// coeff linearisation
	for (i = 0; i < NBR_COEFF_LINEAR;i++) m_ListCoeffLinear.pAdd(new CElemFloat());
	_stprintf(szText2,_T("0x%08x|m_ListCoeffLinear|1.0|2.0|3.0|4.0|5.0|6.0|7.0|8.0|9.0|10.0"),MAKE_ID(iNumStream, iNumMesure,eTYPE_LIST,eID_MESURE_LIST_COEFF_LINEAR));
	dwGetPrivateProfileString(szRub,_T("m_ListCoeffLinear"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListCoeffLinear.bSetConfig(szText);
	// liste des moyennes
	for (i = 0; i < NBR_MESURE_MOY;i++) m_ListMesureMoy.pAdd(new CElemFloat());
	_stprintf(szText2,_T("0x%08x|m_ListMesureMoy|0|0|0|0|0|0|0|0|0|0"),MAKE_ID(iNumStream, iNumMesure,eTYPE_LIST,eID_MESURE_LIST_MOYENNE));
	dwGetPrivateProfileString(szRub,_T("m_ListMesureMoy"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListMesureMoy.bSetConfig(szText);
	// données temps-reels
	for (i = 0; i < NBR_REALTIME_DATA;i++) m_ListRealtimeData.pAdd(new CElemFloat());
	_stprintf(szText2,_T("0x%08x|m_ListRealtimeData|1.0|2.0|3.0|4.0|5.0|6.0|7.0|8.0|9.0|10.0"),MAKE_ID(iNumStream, iNumMesure,eTYPE_LIST,eID_MESURE_LIST_REALTIMEDATA));
	dwGetPrivateProfileString(szRub,_T("m_ListRealtimeData"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ListRealtimeData.bSetConfig(szText);




	// valeur mesure pour Jbus Slave
	_stprintf(szText2,_T("0x%08x|ValJbusSlave|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT16,eID_MESURE_VAL_JBUS_SLAVE),m_ValJbusSlave.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ValJbusSlave"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ValJbusSlave.bSetConfig(szText);
	// coeff multiplicateur valeur mesure pour Jbus Slave
	_stprintf(szText2,_T("0x%08x|m_CoeffValJbusSlave|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT16,eID_MESURE_COEFF_VAL_JBUS_SLAVE),m_CoeffValJbusSlave.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CoeffValJbusSlave"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CoeffValJbusSlave.bSetConfig(szText);
	// valeur mesure pour carte IO
	_stprintf(szText2,_T("0x%08x|m_ValAna|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT16,eID_MESURE_VAL_IO),m_ValAna.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ValAna"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ValAna.bSetConfig(szText);
	// valeur conversisseur max pour carte IO
	_stprintf(szText2,_T("0x%08x|m_ValMaxConvertisseur|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT16,eID_MESURE_VAL_IO_MAX_DAC),m_ValMaxConvertisseur.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ValMaxConvertisseur"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ValMaxConvertisseur.bSetConfig(szText);
	// valeur conversisseur min pour carte IO
	_stprintf(szText2,_T("0x%08x|m_ValMinConvertisseur|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT16,eID_MESURE_VAL_IO_MIN_DAC),m_ValMinConvertisseur.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ValMinConvertisseur"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ValMinConvertisseur.bSetConfig(szText);


	// Gain optique
	_stprintf(szText2,_T("0x%08x|m_OpticalGain|1.|.|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_INT16,eID_MESURE_OPTICAL_GAIN),m_OpticalGain.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_OpticalGain"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_OpticalGain.bSetConfig(szText);
	// valeur etalon
	_stprintf(szText2,_T("0x%08x|m_ZeroOpticalMeasurement|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_ZERO_OPTICAL_MEASUREMENT),m_ZeroOpticalMeasurement.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ZeroOpticalMeasurement"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ZeroOpticalMeasurement.bSetConfig(szText);
	// mesure absorbance
	_stprintf(szText2,_T("0x%08x|m_AbsorbanceValue|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_ABSORBANCE_VALUE),m_AbsorbanceValue.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AbsorbanceValue"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AbsorbanceValue.bSetConfig(szText);
	// valeur étalon avant
	_stprintf(szText2,_T("0x%08x|m_StandardValueBefore|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_STANDARD_VALUE_BEFORE),m_StandardValueBefore.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StandardValueBefore"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StandardValueBefore.bSetConfig(szText);
	// valeur étalon après
	_stprintf(szText2,_T("0x%08x|m_StandardValueAfter|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_STANDARD_VALUE_AFTER),m_StandardValueAfter.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StandardValueAfter"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StandardValueAfter.bSetConfig(szText);
	// ancien coeff de calib
	_stprintf(szText2,_T("0x%08x|m_CalibCoeffNew|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_CALIB_COEFF_NEW),m_CalibCoeffNew.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CalibCoeffNew"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CalibCoeffNew.bSetConfig(szText);
	// mesure optique
	_stprintf(szText2,_T("0x%08x|m_OpticalMeasurement|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_OPTICAL_MEASUREMENT),m_OpticalMeasurement.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_OpticalMeasurement"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_OpticalMeasurement.bSetConfig(szText);
	// absorbance de reference 
	_stprintf(szText2,_T("0x%08x|m_AbsorbanceReference|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_ABSORBANCE_REFERENCE),m_AbsorbanceReference.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AbsorbanceReference"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AbsorbanceReference.bSetConfig(szText);
	// concentration brut 
	_stprintf(szText2,_T("0x%08x|m_RawConcentration|1.|mV|%s"),MAKE_ID(iNumStream, iNumMesure,eTYPE_FLOAT,eID_MESURE_RAW_CONCENTRATION),m_RawConcentration.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_RawConcentration"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_RawConcentration.bSetConfig(szText);
	
	// Absorbance corrigé
	_stprintf( szText2,_T("0x%08x|m_CorrectedAbsorbance|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_CORRECTED_ABSORBANCE)
		    , m_CorrectedAbsorbance.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CorrectedAbsorbance"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CorrectedAbsorbance.bSetConfig(szText);

	//Absorbance réel
	_stprintf( szText2,_T("0x%08x|m_RealAbsorbance|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_REAL_ABSORBANCE)
		    , m_RealAbsorbance.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_RealAbsorbance"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_RealAbsorbance.bSetConfig(szText);

	//Delta entre deux mesures 
	_stprintf( szText2,_T("0x%08x|m_Delta|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_DELTA)
		    , m_Delta.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Delta"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Delta.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_CalibZeroWaterNew|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_CALIB_ZERO_WATER_NEW)
		    , m_CalibZeroWaterNew.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CalibZeroWaterNew"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CalibZeroWaterNew.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_AirSetPointAdjustement|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_INT16
					  , eID_MESURE_AIR_SETPOINT_ADJUSTEMENT)
		    , m_AirSetPointAdjustement.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AirSetPointAdjustement"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AirSetPointAdjustement.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_AirRefMeasureRedrSync|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_AIR_REF_MEASURE_REDRSYNC)
		    , m_AirRefMeasureRedrSync.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AirRefMeasureRedrSync"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AirRefMeasureRedrSync.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_AirWaterFlag|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_AIR_WATER_FLAG)
		    , m_AirWaterFlag.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AirWaterFlag"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AirWaterFlag.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_RefBaseline|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_REF_BASELINE)
		    , m_RefBaseline.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_RefBaseline"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_RefBaseline.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_Water90|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_WATER_90)
		    , m_Water90.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Water90"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Water90.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_Turbidity90|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_TURBIDITY_90)
		    , m_Turbidity90.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Turbidity90"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Turbidity90.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_TurbidityFinal|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_TURBIDITY_FINAL)
		    , m_TurbidityFinal.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_TurbidityFinal"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_TurbidityFinal.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_TurbidityCoef|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_TURBIDITY_COEF)
		    , m_TurbidityCoef.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_TurbidityCoef"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_TurbidityCoef.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_TurbidityStandard|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_TURBIDITY_STANDARD)
		    , m_TurbidityStandard.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_TurbidityStandard"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_TurbidityStandard.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_AirOpticalGain|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_AIR_OPTICAL_GAIN)
		    , m_AirOpticalGain.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AirOpticalGain"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AirOpticalGain.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_AirRedrSync|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_AIR_REDRSYNC)
		    , m_AirRedrSync.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AirRedrSync"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AirRedrSync.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_AbsorbanceTurbidity180|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_ABSORBANCE_TURBIDITY_180)
		    , m_AbsorbanceTurbidity180.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AbsorbanceTurbidity180"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AbsorbanceTurbidity180.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_AbsorbanceCorrected|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_ABSORBANCE_CORRECTED)
		    , m_AbsorbanceCorrected.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AbsorbanceCorrected"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AbsorbanceCorrected.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_OpticalGain90|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_INT16
					  , eID_MESURE_OPTICAL_GAIN_90)
		    , m_OpticalGain90.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_OpticalGain90"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_OpticalGain90.bSetConfig(szText);
	
	_stprintf( szText2,_T("0x%08x|m_CourantLedColo|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_COURANT_LED_COLO)
		    , m_CourantLedColo.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CourantLedColo"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CourantLedColo.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_MeasureSetByLed|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_MEASURE_BY_LED)
		    , m_MeasureSetByLed.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_MeasureSetByLed"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_MeasureSetByLed.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_Turbidity|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_TURBIDITY)
		    , m_Turbidity.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Turbidity"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Turbidity.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_Temperature|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_TEMPERATURE)
		    , m_Temperature.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_Temperature"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_Temperature.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_ZeroStandard|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_ZERO_STANDARD)
		    , m_ZeroStandard.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_ZeroStandard"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_ZeroStandard.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_CoefDilution|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_COEF_DILUTION)
		    , m_CoefDilution.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CoefDilution"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CoefDilution.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_CoefAjustement|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_FLOAT
					  , eID_MESURE_COEF_AJUSTEMENT)
		    , m_CoefAjustement.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_CoefAjustement"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_CoefAjustement.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_StatusSonde|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_INT8
					  , eID_LISTSTREAM_STATUS_SONDE)
		    , m_StatusSonde.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StatusSonde"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StatusSonde.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_StatusConcentration|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_INT8
					  , eID_LISTSTREAM_STATUS_CONCENTRATION)
		    , m_StatusConcentration.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_StatusConcentration"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_StatusConcentration.bSetConfig(szText);

	_stprintf( szText2,_T("0x%08x|m_AlarmDelta|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_INT8
					  , eID_MESURE_ALARM_DELTA)
		    , m_AlarmDelta.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AlarmDelta"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AlarmDelta.bSetConfig(szText);

    _stprintf( szText2,_T("0x%08x|m_AlarmDelta2|1.|mV|%s")
			 , MAKE_ID( iNumStream
				      , iNumMesure
					  , eTYPE_INT8
					  , eID_MESURE_ALARM_DELTA2)
		    , m_AlarmDelta2.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(szRub,_T("m_AlarmDelta2"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	m_AlarmDelta2.bSetConfig(szText);


// numéro de programme
	_stprintf( szText2,_T("0x%x|m_NumProgram|0|.|%s")
		     , MAKE_ID( iNumStream
			          , iNumMesure
					  , eTYPE_INT8
					  , eID_MESURE_NUM_PROGRAM)
					  , m_NumProgram.m_szFormat.szGetLabel());
	dwGetPrivateProfileString(_T("CListStream"),_T("m_NumProgram"),szText2,szText,sizeof(szText)/sizeof(TCHAR),pszFileName);
	if (bReturn) bReturn = m_NumProgram.bSetConfig(szText);

	if (!bReturn) 
	{
		TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
		m_StatusFailure.bSetVal(1);
	}
	return bReturn;
}

BOOL CMesure::bWriteConfig(int iNumStream, int iNumMesure, LPCTSTR pszFileName)
{
	BOOL bReturn = FALSE;
	TCHAR szRub[MAX_PATH];
	TCHAR szText[MAX_PATH];

	_stprintf(szRub,_T("CStream%d_CMesure%d"),iNumStream, iNumMesure);
	// StatusFailure
	bReturn = bWritePrivateProfileString(szRub,_T("m_StatusFailure"),m_StatusFailure.szGetConfig(szText,MAX_PATH),pszFileName);
	// mesure
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Val"),m_Val.szGetConfig(szText,MAX_PATH),pszFileName);
	// valeur MIN MAX
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ValMax"),m_ValMax.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ValMin"),m_ValMin.szGetConfig(szText,MAX_PATH),pszFileName);
	// seuil
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Threshold1"),m_Threshold1.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Threshold2"),m_Threshold2.szGetConfig(szText,MAX_PATH),pszFileName);
	// status seuil
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StatusThreshold1"),m_StatusThreshold1.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StatusThreshold2"),m_StatusThreshold2.szGetConfig(szText,MAX_PATH),pszFileName);
	// 4/20
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AnalogZero"),m_AnalogZero.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AnalogPlage"),m_AnalogPlage.szGetConfig(szText,MAX_PATH),pszFileName);


	// Coeff de calibration
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CalibCoeff"),m_CalibCoeff.szGetConfig(szText,MAX_PATH),pszFileName);
	// calib zero water
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CalibZeroWater"),m_CalibZeroWater.szGetConfig(szText,MAX_PATH),pszFileName);
	// calib zero air
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CalibZeroAir"),m_CalibZeroAir.szGetConfig(szText,MAX_PATH),pszFileName);
	// status calib coeff
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CalibStatusCoeff"),m_CalibStatusCoeff.szGetConfig(szText,MAX_PATH),pszFileName);
	// status calib zero
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CalibStatusZero"),m_CalibStatusZero.szGetConfig(szText,MAX_PATH),pszFileName);
	//Type de seuils 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_SettingThreshold"),m_SettingThreshold.szGetConfig(szText,MAX_PATH),pszFileName);
	
	// coeff linearisation
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListCoeffLinear"),m_ListCoeffLinear.szGetConfig(szText,MAX_PATH),pszFileName);
	// liste des moyennes
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListMesureMoy"),m_ListMesureMoy.szGetConfig(szText,MAX_PATH),pszFileName);
	// données temps-reels
	//m_ListRealtimeData.RemoveAll();
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ListRealtimeData"),m_ListRealtimeData.szGetConfig(szText,MAX_PATH),pszFileName);


	// valeur mesure pour Jbus Slave
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ValJbusSlave"),m_ValJbusSlave.szGetConfig(szText,MAX_PATH),pszFileName);
	// coeff multiplicateur valeur mesure pour Jbus Slave
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CoeffValJbusSlave"),m_CoeffValJbusSlave.szGetConfig(szText,MAX_PATH),pszFileName);
	// valeur mesure pour carte IO
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ValAna"),m_ValAna.szGetConfig(szText,MAX_PATH),pszFileName);
	// valeur conversisseur max pour carte IO
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ValMaxConvertisseur"),m_ValMaxConvertisseur.szGetConfig(szText,MAX_PATH),pszFileName);
	// valeur conversisseur min pour carte IO
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ValMinConvertisseur"),m_ValMinConvertisseur.szGetConfig(szText,MAX_PATH),pszFileName);


	// Gain optique
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_OpticalGain"),m_OpticalGain.szGetConfig(szText,MAX_PATH),pszFileName);
	// valeur etalon
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ZeroOpticalMeasurement"),m_ZeroOpticalMeasurement.szGetConfig(szText,MAX_PATH),pszFileName);
	// mesure absorbance
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AbsorbanceValue"),m_AbsorbanceValue.szGetConfig(szText,MAX_PATH),pszFileName);
	// valeur étalon avant
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StandardValueBefore"),m_StandardValueBefore.szGetConfig(szText,MAX_PATH),pszFileName);
	// valeur étalon après
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StandardValueAfter"),m_StandardValueAfter.szGetConfig(szText,MAX_PATH),pszFileName);
	// ancien coeff de calib
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CalibCoeffNew"),m_CalibCoeffNew.szGetConfig(szText,MAX_PATH),pszFileName);
	// mesure optique
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_OpticalMeasurement"),m_OpticalMeasurement.szGetConfig(szText,MAX_PATH),pszFileName);
	// absorbance de reference 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AbsorbanceReference"),m_AbsorbanceReference.szGetConfig(szText,MAX_PATH),pszFileName);
	// concentration brut 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_RawConcentration"),m_RawConcentration.szGetConfig(szText,MAX_PATH),pszFileName);
	
	// Absorbance corrigé 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CorrectedAbsorbance"),m_CorrectedAbsorbance.szGetConfig(szText,MAX_PATH),pszFileName);
	//Absorbance réel
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_RealAbsorbance"),m_RealAbsorbance.szGetConfig(szText,MAX_PATH),pszFileName);
	//Delta entre deux mesures 
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Delta"),m_Delta.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CalibZeroWaterNew"),m_CalibZeroWaterNew.szGetConfig(szText,MAX_PATH),pszFileName);
    // numéro programme
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_NumProgram"),m_NumProgram.szGetConfig(szText,MAX_PATH),pszFileName);
	
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AirSetPointAdjustement"),m_AirSetPointAdjustement.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AirRefMeasureRedrSync"),m_AirRefMeasureRedrSync.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AirWaterFlag"),m_AirWaterFlag.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_RefBaseline"),m_RefBaseline.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Water90"),m_Water90.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Turbidity90"),m_Turbidity90.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_TurbidityFinal"),m_TurbidityFinal.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_TurbidityCoef"),m_TurbidityCoef.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_TurbidityStandard"),m_TurbidityStandard.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AirOpticalGain"),m_AirOpticalGain.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AirRedrSync"),m_AirRedrSync.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AbsorbanceTurbidity180"),m_AbsorbanceTurbidity180.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AbsorbanceCorrected"),m_AbsorbanceCorrected.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_OpticalGain90"),m_OpticalGain90.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CourantLedColo"),m_CourantLedColo.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_MeasureSetByLed"),m_MeasureSetByLed.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Turbidity"),m_Turbidity.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_Temperature"),m_Temperature.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_ZeroStandard"),m_ZeroStandard.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CoefDilution"),m_CoefDilution.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_CoefAjustement"),m_CoefAjustement.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StatusSonde"),m_StatusSonde.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_StatusConcentration"),m_StatusConcentration.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AlarmDelta"),m_AlarmDelta.szGetConfig(szText,MAX_PATH),pszFileName);
	if (bReturn) bReturn = bWritePrivateProfileString(szRub,_T("m_AlarmDelta2"),m_AlarmDelta2.szGetConfig(szText,MAX_PATH),pszFileName);

	if (!bReturn) TRACE_DEBUG(eDebug,eConfig,_T(__FILE__),_T(__FUNCTION__),__LINE__,_T("Error: %s"),szGetLabel());
	return bReturn;
}


BOOL CMesure::bTraitement(CElemInt8* argNumCurrentStream)
{
	BOOL bReturn = TRUE;
	float fTemp;

	//DEBUT traitement du seuil de la mesure
	if(m_SettingThreshold.ucGetVal() == 2) //Deux seuils haut
	{
		if(m_Val.fGetVal() > m_Threshold1.fGetVal())
		{
			m_StatusThreshold1.bSetVal(1);
			TRACE_DEBUG_IHM(eError,eMesure,eErrorMesureStatusThreshold1, argNumCurrentStream);
			bReturn = FALSE;
		}
		else
		{
			m_StatusThreshold1.bSetVal(0);
		}
		
		if (m_Val.fGetVal() > m_Threshold2.fGetVal())
		{
			m_StatusThreshold2.bSetVal(1);
			TRACE_DEBUG_IHM(eError,eMesure,eErrorMesureStatusThreshold2, argNumCurrentStream);
			bReturn = FALSE;
		}
		else
		{
			m_StatusThreshold2.bSetVal(0);
		}
	} else if (m_SettingThreshold.ucGetVal() == 1) //1 seuil bas/1 seuil haut
	{
		if(m_Val.fGetVal() < m_Threshold1.fGetVal())
		{
			m_StatusThreshold1.bSetVal(1);
			TRACE_DEBUG_IHM(eError,eMesure,eErrorMesureStatusThreshold1, argNumCurrentStream);
			bReturn = FALSE;
		}
		else
		{
			m_StatusThreshold1.bSetVal(0);
		}
		
		if (m_Val.fGetVal() > m_Threshold2.fGetVal())
		{
			m_StatusThreshold2.bSetVal(1);
			TRACE_DEBUG_IHM(eError,eMesure,eErrorMesureStatusThreshold2, argNumCurrentStream);
			bReturn = FALSE;
		}
		else
		{
			m_StatusThreshold2.bSetVal(0);
		}
	}else //if (m_SettingThreshold.ucGetVal() == 0) Deux seuils bas (par defaut en cas de valeur éronné).
	{
		if(m_Val.fGetVal() < m_Threshold1.fGetVal())
		{
			m_StatusThreshold1.bSetVal(1);
			TRACE_DEBUG_IHM(eError,eMesure,eErrorMesureStatusThreshold1, argNumCurrentStream);
			bReturn = FALSE;
		}
		else
		{
			m_StatusThreshold1.bSetVal(0);
		}
		
		if (m_Val.fGetVal() < m_Threshold2.fGetVal())
		{
			m_StatusThreshold2.bSetVal(1);
			TRACE_DEBUG_IHM(eError,eMesure,eErrorMesureStatusThreshold2, argNumCurrentStream);
			bReturn = FALSE;
		}
		else
		{
			m_StatusThreshold2.bSetVal(0);
		}
	}

	//FIN gestion seuils

	// traitement val min max
	if (m_Val.fGetVal() > m_ValMax.fGetVal()) 
	{
		m_Val.bSetVal(m_ValMax.fGetVal());
		TRACE_DEBUG_IHM(eError,eMesure,eErrorMesureValMax);
		bReturn = FALSE;
	}
	if (m_Val.fGetVal() < m_ValMin.fGetVal()) 
	{
		m_Val.bSetVal(m_ValMin.fGetVal());
		TRACE_DEBUG_IHM(eError,eMesure,eErrorMesureValMin);
		bReturn = FALSE;
	}

	// calcul valeur sur JBUS esclave
	m_ValJbusSlave.bSetVal((short)(m_Val.fGetVal() * m_CoeffValJbusSlave.fGetVal()));

	fTemp = m_Val.fGetVal();
	if (fTemp > m_AnalogPlage.fGetVal()) 
	{
		fTemp = m_AnalogPlage.fGetVal();
	}
	if (fTemp < m_AnalogZero.fGetVal()) 
	{
		fTemp = m_AnalogZero.fGetVal();
	}
	// calcul de la valeur JBUS maitre IO
	if (m_AnalogPlage.fGetVal() > m_AnalogZero.fGetVal())
	{
		m_ValAna.bSetVal((short)( (m_ValMaxConvertisseur.nGetVal() - m_ValMinConvertisseur.nGetVal()) * (fTemp - m_AnalogZero.fGetVal()) / (m_AnalogPlage.fGetVal() - m_AnalogZero.fGetVal()) ) + m_ValMinConvertisseur.nGetVal()) ;
	}
	else
	{
		m_ValAna.bSetVal(m_ValMaxConvertisseur.nGetVal());
	}

	return bReturn;
}
