#pragma once
#include "header_qt.h"
#include "header.h"

class CMesureModel 
{

public:
	CMesureModel(void);
	

	void setpMesure(CMesure* argpMesure) {m_pMesure = argpMesure;initm_mapIdRefVar();};
	void setName(QString argName){m_sName = argName;};
	void setUnite(QString argUnite){m_sUnite = argUnite;};
	void setValeur(float argValeur){m_fValeur = argValeur;};

	QString getName(){return m_sName;};
	QString getUnite(){return m_sUnite;};
	float getValeur(){return m_fValeur;};
	
	
	QString getVarMesureValeur(QString argsObjectName);
	QString getVarMesureLbl(QString argsObjectName);
	QString getVarMesureUnit(QString argsObjectName);
	void	setVarMesureValeur(QString argsObjectName, QString argsObjectKey, QString arg_sValue);
	static void writeElemConfigIni(WCHAR* arg_szSection, WCHAR* arg_szElemName, CElemBase* arg_pCElemBase);
	/*QString setVal(){};
	QString getVal(){return QString::number(m_pMesure->m_Val.fGetVal(), 'f', 2);};
	QString getValRef(){return m_pMesure->m_Val;};
	QString getValLbl(){return QString::fromUtf16(( const ushort *)m_pMesure->m_Val.szGetLabel()
													   , m_pMesure->m_Val.lGetLabelLength());};
	QString getValUnit(){return QString::fromUtf16(( const ushort *)m_pMesure->m_Val.m_szUnit.szGetLabel()
													   , m_pMesure->m_Val.m_szUnit.lGetLabelLength());};
	
	
	QString getValFormat(){};
	QString setValMax(){};
	QString getValMax(){};
	QString getValMaxLbl(){};
	QString getValMaxUnit(){};
	QString getValMaxFormat(){};
	QString setValMin(){};
	QString getValMin(){};
	QString getValMinLbl(){};
	QString getValMinUnit(){};
	QString getValMinFormat(){};
	QString setStatusFailure(){};
	QString getStatusFailure(){};
	QString getStatusFailureLbl(){};
	QString getStatusFailureUnit(){};
	QString getStatusFailureFormat(){};
	QString setThreshold1(){};
	QString getThreshold1(){};
	QString getThreshold1Lbl(){};
	QString getThreshold1Unit(){};
	QString getThreshold1Format(){};
	QString setThreshold2(){};
	QString getThreshold2(){};
	QString getThreshold2Lbl(){};
	QString getThreshold2Unit(){};
	QString getThreshold2Format(){};
	QString setStatusThreshold1(){};
	QString getStatusThreshold1(){};
	QString getStatusThreshold1Lbl(){};
	QString getStatusThreshold1Unit(){};
	QString getStatusThreshold1Format(){};
	QString setStatusThreshold2(){};
	QString getStatusThreshold2(){};
	QString getStatusThreshold2Lbl(){};
	QString getStatusThreshold2Unit(){};
	QString getStatusThreshold2Format(){};
	QString setAnalogZero(){};
	QString getAnalogZero(){};
	QString getAnalogZeroLbl(){};
	QString getAnalogZeroUnit(){};
	QString getAnalogZeroFormat(){};
	QString setAnalogPlage(){};
	QString getAnalogPlage(){};
	QString getAnalogPlageLbl(){};
	QString getAnalogPlageUnit(){};
	QString getAnalogPlageFormat(){};
	QString setCalibCoeff(){};
	QString getCalibCoeff(){};
	QString getCalibCoeffLbl(){};
	QString getCalibCoeffUnit(){};
	QString getCalibCoeffFormat(){};
	QString setCalibZeroWater(){};
	QString getCalibZeroWater(){};
	QString getCalibZeroWaterLbl(){};
	QString getCalibZeroWaterUnit(){};
	QString getCalibZeroWaterFormat(){};
	QString setCalibZeroAir(){};
	QString getCalibZeroAir(){};
	QString getCalibZeroAirLbl(){};
	QString getCalibZeroAirUnit(){};
	QString getCalibZeroAirFormat(){};
	QString setCalibStatusCoeff(){};
	QString getCalibStatusCoeff(){};
	QString getCalibStatusCoeffLbl(){};
	QString getCalibStatusCoeffUnit(){};
	QString getCalibStatusCoeffFormat(){};
	QString setCalibStatusZero(){};
	QString getCalibStatusZero(){};
	QString getCalibStatusZeroLbl(){};
	QString getCalibStatusZeroUnit(){};
	QString getCalibStatusZeroFormat(){};
	QString setSettingThreshold(){};
	QString getSettingThreshold(){};
	QString getSettingThresholdLbl(){};
	QString getSettingThresholdUnit(){};
	QString getSettingThresholdFormat(){};
	QString setValJbusSlave(){};
	QString getValJbusSlave(){};
	QString getValJbusSlaveLbl(){};
	QString getValJbusSlaveUnit(){};
	QString getValJbusSlaveFormat(){};
	QString setCoeffValJbusSlave(){};
	QString getCoeffValJbusSlave(){};
	QString getCoeffValJbusSlaveLbl(){};
	QString getCoeffValJbusSlaveUnit(){};
	QString getCoeffValJbusSlaveFormat(){};
	QString setValAna(){};
	QString getValAna(){};
	QString getValAnaLbl(){};
	QString getValAnaUnit(){};
	QString getValAnaFormat(){};
	QString setValMaxConvertisseur(){};
	QString getValMaxConvertisseur(){};
	QString getValMaxConvertisseurLbl(){};
	QString getValMaxConvertisseurUnit(){};
	QString getValMaxConvertisseurFormat(){};
	QString setValMinConvertisseur(){};
	QString getValMinConvertisseur(){};
	QString getValMinConvertisseurLbl(){};
	QString getValMinConvertisseurUnit(){};
	QString getValMinConvertisseurFormat(){};
	QString setListCoeffLinear(){};
	QString getListCoeffLinear(){};
	QString getListCoeffLinearLbl(){};
	QString getListCoeffLinearUnit(){};
	QString getListCoeffLinearFormat(){};
	QString setListMesureMoy(){};
	QString getListMesureMoy(){};
	QString getListMesureMoyLbl(){};
	QString getListMesureMoyUnit(){};
	QString getListMesureMoyFormat(){};
	QString setListRealtimeData(){};
	QString getListRealtimeData(){};
	QString getListRealtimeDataLbl(){};
	QString getListRealtimeDataUnit(){};
	QString getListRealtimeDataFormat(){};
	QString setOpticalGain(){};
	QString getOpticalGain(){};
	QString getOpticalGainLbl(){};
	QString getOpticalGainUnit(){};
	QString getOpticalGainFormat(){};
	QString setZeroOpticalMeasurement(){};
	QString getZeroOpticalMeasurement(){};
	QString getZeroOpticalMeasurementLbl(){};
	QString getZeroOpticalMeasurementUnit(){};
	QString getZeroOpticalMeasurementFormat(){};
	QString setAbsorbanceValue(){};
	QString getAbsorbanceValue(){};
	QString getAbsorbanceValueLbl(){};
	QString getAbsorbanceValueUnit(){};
	QString getAbsorbanceValueFormat(){};
	QString setStandardValueBefore(){};
	QString getStandardValueBefore(){};
	QString getStandardValueBeforeLbl(){};
	QString getStandardValueBeforeUnit(){};
	QString getStandardValueBeforeFormat(){};
	QString setStandardValueAfter(){};
	QString getStandardValueAfter(){};
	QString getStandardValueAfterLbl(){};
	QString getStandardValueAfterUnit(){};
	QString getStandardValueAfterFormat(){};
	QString setCalibCoeffNew(){};	
	QString getCalibCoeffNew(){};	
	QString getCalibCoeffNewLbl(){};	
	QString getCalibCoeffNewUnit(){};	
	QString getCalibCoeffNewFormat(){};	
	QString setOpticalMeasurement(){};
	QString getOpticalMeasurement(){};
	QString getOpticalMeasurementLbl(){};
	QString getOpticalMeasurementUnit(){};
	QString getOpticalMeasurementFormat(){};
	QString setAbsorbanceReference(){};
	QString getAbsorbanceReference(){};
	QString getAbsorbanceReferenceLbl(){};
	QString getAbsorbanceReferenceUnit(){};
	QString getAbsorbanceReferenceFormat(){};
	QString setRawConcentration(){};
	QString getRawConcentration(){};
	QString getRawConcentrationLbl(){};
	QString getRawConcentrationUnit(){};
	QString getRawConcentrationFormat(){};
	QString setCorrectedAbsorbance(){};
	QString getCorrectedAbsorbance(){};
	QString getorrectedAbsorbanceLbl(){};
	QString getCorrectedAbsorbanceUnit(){};
	QString getCorrectedAbsorbanceFormat(){};
	QString setRealAbsorbance(){};
	QString getRealAbsorbance(){};
	QString getRealAbsorbanceLbl(){};
	QString getRealAbsorbanceUnit(){};
	QString getRealAbsorbanceFormat(){};
	QString setDelta(){};
	QString getDelta(){};
	QString getDeltaLbl(){};
	QString getDeltaUnit(){};
	QString getDeltaFormat(){};
	QString setCalibZeroWaterNew(){};
	QString getCalibZeroWaterNew(){};
	QString getCalibZeroWaterNewLbl(){};
	QString getCalibZeroWaterNewUnit(){};
	QString getCalibZeroWaterNewFormat(){};
    QString setNumProgram(){};
    QString getNumProgram(){};
    QString getNumProgramLbl(){};
    QString getNumProgramUnit(){};
    QString getNumProgramFormat(){};
	QString setSommeMesure(){};
	QString getSommeMesure(){};
	QString getSommeMesureLbl(){};
	QString getSommeMesureUnit(){};
	QString getSommeMesureFormat(){};*/

private:
	//Référence sur la supervision
	CMesure* m_pMesure;

	//Map associent les ID text des variable superviseur aux ref des variable superviseur
	QMap<long, CElemNbr*> m_mapIdRefVar; 

	QString m_sName;
	QString m_sUnite;
	float m_fValeur;

	void initm_mapIdRefVar();
};
