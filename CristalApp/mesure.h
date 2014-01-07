#pragma once

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
#define NBR_COEFF_LINEAR		20
#define NBR_MESURE_MOY			20
#define NBR_REALTIME_DATA		20

class  CMesure : public CElemBase
{
public:
	CMesure(BYTE ucNumVoie,BYTE ucNumMesure);
	CMesure();
	virtual ~CMesure();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);

public:
	BOOL bReadConfig(int iNumStream, int iNumMesure, LPCTSTR pszFileName);
	BOOL bWriteConfig(int iNumStream, int iNumMesure, LPCTSTR pszFileName);
	BOOL bTraitement(CElemInt8* argNumCurrentStream);

public:
	CElemFloat m_Val;
	CElemFloat m_ValMax;
	CElemFloat m_ValMin;
	CElemInt8 m_StatusFailure;
	CElemFloat m_Threshold1;
	CElemFloat m_Threshold2;
	CElemInt8 m_StatusThreshold1;
	CElemInt8 m_StatusThreshold2;
	CElemFloat m_AnalogZero;
	CElemFloat m_AnalogPlage;
	CElemFloat m_CalibCoeff;
	CElemFloat m_CalibZeroWater;
	CElemFloat m_CalibZeroAir;
	CElemInt8 m_CalibStatusCoeff;
	CElemInt8 m_CalibStatusZero;
	CElemInt8 m_SettingThreshold;
	CElemInt16 m_ValJbusSlave;
	CElemFloat m_CoeffValJbusSlave;
	CElemInt16 m_ValAna;
	CElemInt16 m_ValMaxConvertisseur;
	CElemInt16 m_ValMinConvertisseur;
	CElemList m_ListCoeffLinear;
	CElemList m_ListMesureMoy;
	CElemList m_ListRealtimeData;
	// Gain optique
	CElemInt16 m_OpticalGain;
	// valeur etalon
	CElemFloat m_ZeroOpticalMeasurement;
	// mesure absorbance
	CElemFloat m_AbsorbanceValue;
	// valeur étalon avant
	CElemFloat m_StandardValueBefore;
	// valeur étalon après
	CElemFloat m_StandardValueAfter;
	// ancien coeff de calib
	CElemFloat m_CalibCoeffNew;
	// mesure optique
	CElemFloat m_OpticalMeasurement;
	// absorbance de reference 
	CElemFloat m_AbsorbanceReference;
	// concentration brut 
	CElemFloat m_RawConcentration;
	//Absorbance corrigé
	CElemFloat m_CorrectedAbsorbance;
	//Absorbance réel
	CElemFloat m_RealAbsorbance;
	//Delta entre deux mesures
	CElemFloat m_Delta;
	CElemFloat m_CalibZeroWaterNew;
	//Numéro du programme qui à finit d'être executé sur la carte mesure
    CElemInt8 m_NumProgram;

	//DEBUT variables pour les sondes/couleur
	//Consigne réglage air
	CElemInt16 m_AirSetPointAdjustement;
	//mesure air redr synchrone ref
	CElemFloat m_AirRefMeasureRedrSync;
	//Indicateur eau-air
	CElemFloat m_AirWaterFlag;
	//ligne de base référence
	CElemFloat m_RefBaseline;
	//mesure eau 90°
	CElemFloat m_Water90;
	//mesure turbidité 90°
	CElemFloat m_Turbidity90;
	//Mesure turbudité final
	CElemFloat m_TurbidityFinal;
	//coef turbidité
	CElemFloat m_TurbidityCoef;
	//etalon turbidité
	CElemFloat m_TurbidityStandard;
	//mesure gain optique air
	CElemFloat m_AirOpticalGain;
	//mesure air redrSync
	CElemFloat m_AirRedrSync;
	//absorbance turbidité 180°
	CElemFloat m_AbsorbanceTurbidity180;
	//absorbance compensée
	CElemFloat m_AbsorbanceCorrected;
	//mesure gain optique 90°
	CElemInt16 m_OpticalGain90;
	//mesure courant led colo
	CElemFloat m_CourantLedColo;
	//mesure réglée par led
	CElemFloat m_MeasureSetByLed;
	//turbidité
	CElemFloat m_Turbidity;
	//température
	CElemFloat m_Temperature;
	//étalon zero
	CElemFloat m_ZeroStandard;
	//Coefficient de dilution
	CElemFloat m_CoefDilution;
	//Coefficient d'ajustement
	CElemFloat m_CoefAjustement;

	CElemInt8 m_StatusSonde;
	CElemInt8 m_StatusConcentration;
	CElemInt8 m_AlarmDelta;
	CElemInt8 m_AlarmDelta2;
	//FIN var pour les sondes/couleur
	
	
	//Variable non définie dans le fichier de conf
	CElemFloat m_SommeMesure;
	int m_iCompteurMesure;
};

