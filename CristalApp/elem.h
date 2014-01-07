#pragma once
#include <QString>

#define NUM_VERSION_0						0
#define NUM_VERSION_1						1
#define NUM_VERSION_2						2
#define NUM_VERSION_3						3
#define NUM_VERSION_4						4
#define NUM_VERSION_5						5
#define NUM_LAST_VERSION					NUM_VERSION_5


#define NUM_VOIE(a)							((BYTE)(a >> 24))
#define NUM_MESURE(a)						((BYTE)((a >> 16) & 0x000000FF))
#define NUM_TYPE(a)							((BYTE)((a >> 8)  & 0x000000FF))
#define NUM_ID(a)							((BYTE)(a & 0x000000FF))
#define MAKE_ID(iVoie,iMesure,iType,iId)	((iVoie << 24) | (iMesure << 16) | (iType << 8) | iId)


enum eTypeElem{
	eTYPE_TXT	= 0,
	eTYPE_BITFIELD8	,			
	eTYPE_BITFIELD16,			
	eTYPE_INT8	,			
	eTYPE_INT16	,			
	eTYPE_INT32	,			
	eTYPE_FLOAT	,
	eTYPE_MESURE,
	eTYPE_VOIE,
	eTYPE_LIST,
	eTYPE_JBUS_TRAME,
	eTYPE_JBUS_EXCHANGE,
	eTYPE_CYCLE_STEP,
	eTYPE_CYCLE,
	eTYPE_CYCLE_ZERO,
	eTYPE_CYCLE_CALIB,
	eTYPE_CYCLE_CLEANUP,
	eTYPE_LIST_VOIE,
};

enum eID{
	eID_MESURE_STATUS_FAILURE = 0,
	eID_MESURE_VAL,
	eID_MESURE_THRESHOLD1,
	eID_MESURE_THRESHOLD2,
	eID_MESURE_STATUS_THRESHOLD1,
	eID_MESURE_STATUS_THRESHOLD2,
	eID_MESURE_VALMIN,
	eID_MESURE_VALMAX,
	eID_MESURE_ANALOG_ZERO,
	eID_MESURE_ANALOG_PLAGE,
	eID_MESURE_CALIB_COEFF,
	eID_MESURE_CALIB_ZERO_WATER,
	eID_MESURE_CALIB_ZERO_AIR,
	eID_MESURE_CALIB_STATUS_COEFF,
	eID_MESURE_CALIB_STATUS_ZERO,
	eID_MESURE_LIST_COEFF_LINEAR,
	eID_MESURE_LIST_MOYENNE,
	eID_MESURE_LIST_REALTIMEDATA,
	eID_MESURE_VAL_JBUS_SLAVE,
	eID_MESURE_COEFF_VAL_JBUS_SLAVE,
	eID_MESURE_VAL_IO,
	eID_MESURE_VAL_IO_MAX_DAC,
	eID_MESURE_VAL_IO_MIN_DAC,

	eID_MESURE_OPTICAL_GAIN,
	eID_MESURE_ZERO_OPTICAL_MEASUREMENT,
	eID_MESURE_ABSORBANCE_VALUE,
	eID_MESURE_STANDARD_VALUE_BEFORE,
	eID_MESURE_STANDARD_VALUE_AFTER,
	eID_MESURE_CALIB_COEFF_NEW,
	eID_MESURE_OPTICAL_MEASUREMENT,
	eID_MESURE_ABSORBANCE_REFERENCE,
	eID_MESURE_RAW_CONCENTRATION,
	eID_MESURE_CORRECTED_ABSORBANCE,
	eID_MESURE_REAL_ABSORBANCE,	
	eID_MESURE_DELTA,	
	eID_MESURE_CALIB_ZERO_WATER_NEW,
	eID_MESURE_SETTING_THRESHOLD, 
	eID_MESURE_LIRBRE_2, //Suite a connerie, peut etre ustilsé pour de futur variable
	eID_MESURE_NUM_PROGRAM, //38

	eID_STREAM_CYCLE_TIME_MAX = 50,
	eID_STREAM_CYCLE_TIME_CURRENT,
	eID_STREAM_ACTIVE,
	eID_STREAM_STATUS_FAILURE,
	eID_STREAM_STATUS_WATER_FAILURE,
	eID_STREAM_IS_RUNNING,
	eID_STREAM_COUNTER_CYCLE,
	eID_STREAM_CURRENT_STEP,
	eID_STREAM_CELL_TEMPERATURE,
	eID_STREAM_WATER_FAILURE_SET_POINT,
	eID_STREAM_OPTICAL_SET_POINT,
	eID_STREAM_CELL_TEMPERATURE_SET_POINT,
	eID_STREAM_PRESSURE_MEASUREMENT,
	eID_STREAM_THRESHOLD_TEMPERATURE_PROBE,
	eID_STREAM_TEMPERATURE_PROBE,
	eID_STREAM_SETTING_COLOR_THRESHOLD1,
	eID_STREAM_SETTING_COLOR_THRESHOLD2,
	eID_STREAM_PERIODIC_CYCLE_CLEANUP,
	eID_STREAM_PERIODIC_CYCLE_ZERO,
	eID_STREAM_PERIODIC_CYCLE_CALIB,
	eID_STREAM_PERIODIC_CYCLE_CALIB_INLINE,
	eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CLEANUP,
	eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_ZERO,
	eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CALIB,
	eID_STREAM_LIST_PERIODIC_HOUR_CYCLE_CALIB_INLINE,
	eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CLEANUP,
	eID_STREAM_LIST_PERIODIC_DAY_CYCLE_ZERO,
	eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CALIB,
	eID_STREAM_LIST_PERIODIC_DAY_CYCLE_CALIB_INLINE,
	eID_STREAM_CONDITIONING_CYCLE_MEASUREMENT,
	eID_STREAM_CONDITIONING_CYCLE_CLEANUP,
	eID_STREAM_CONDITIONING_CYCLE_ZERO,
	eID_STREAM_CONDITIONING_CYCLE_CALIB,
	eID_STREAM_CONDITIONING_CYCLE_CALIB_INLINE,
	eID_STREAM_CONDITIONING_MEASUREMENT,
	eID_STREAM_CONDITIONING_CLEANUP,
	eID_STREAM_CONDITIONING_ZERO,
	eID_STREAM_CONDITIONING_CALIB,
	eID_STREAM_CONDITIONING_CALIB_INLINE,
	eID_STREAM_STATE_CONDITIONING,
	eID_STREAM_NAME,

	eID_LISTSTREAM_NUM_CURRENT_STREAM = 100,
	eID_LISTSTREAM_NUM_CURRENT_CONFIG,
	eID_LISTSTREAM_STATUS_FAILURE,
	eID_LISTSTREAM_CURRENT_TIME_CYCLE,
	eID_LISTSTREAM_STATUS_REALTIME,
	eID_LISTSTREAM_STATE_MAINTENANCE,
	eID_LISTSTREAM_STATE_CALIB,
	eID_LISTSTREAM_STATE_ZERO,
	eID_LISTSTREAM_STATE_CLEANUP,
	eID_LISTSTREAM_LIST_SEQUENCE_NUM,
	eID_LISTSTREAM_LIST_SEQUENCE_DUREE,
	eID_LISTSTREAM_LIST_MESSAGE_ERROR,
	eID_LISTSTREAM_NUM_VERSION,
	eID_LISTSTREAM_CELL_TEMPERATURE_ORDER,
	eID_LISTSTREAM_CELL_OFFSET,
	eID_LISTSTREAM_PROBE_GAIN,
	eID_LISTSTREAM_PROBE_OFFSET,
	eID_LISTSTREAM_STATUS_SUPPERVISION,
	eID_LISTSTREAM_STATE_CALIB_IN_LINE,
	eID_LISTSTREAM_AVERAGE,
	eID_LISTSTREAM_TIMER,

	eID_LISTSTREAM_CMD_LOAD_NUM_CONFIG = 150,
	eID_LISTSTREAM_CMD_SAVE_NUM_CONFIG,
	eID_LISTSTREAM_CMD_RUN,
	eID_LISTSTREAM_CMD_PAUSE,
	eID_LISTSTREAM_CMD_CYCLE_CALIB,
	eID_LISTSTREAM_CMD_CYCLE_ZERO,
	eID_LISTSTREAM_CMD_CYCLE_CLEANUP,
	eID_LISTSTREAM_CMD_JUMP_STEP,
	eID_LISTSTREAM_CMD_REMOTE_CONTROL,
	eID_LISTSTREAM_CMD_STOP_END_CYCLE,
	eID_LISTSTREAM_CMD_CYCLE_CALIB_IN_LINE,
	eID_LISTSTREAM_CMD_MAINTENANCE,

	eID_MESURE_AIR_SETPOINT_ADJUSTEMENT = 200,
	eID_MESURE_AIR_REF_MEASURE_REDRSYNC,
	eID_MESURE_AIR_WATER_FLAG,
	eID_MESURE_REF_BASELINE,
	eID_MESURE_WATER_90,
	eID_MESURE_TURBIDITY_90,
	eID_MESURE_TURBIDITY_FINAL,
	eID_MESURE_TURBIDITY_COEF,
	eID_MESURE_TURBIDITY_STANDARD,
	eID_MESURE_AIR_OPTICAL_GAIN,
	eID_MESURE_AIR_REDRSYNC,
	eID_MESURE_ABSORBANCE_TURBIDITY_180,
	eID_MESURE_ABSORBANCE_CORRECTED,
	eID_MESURE_OPTICAL_GAIN_90,
	eID_MESURE_COURANT_LED_COLO,
	eID_MESURE_MEASURE_BY_LED,
	eID_MESURE_TURBIDITY,
	eID_MESURE_TEMPERATURE,
	eID_MESURE_ZERO_STANDARD,
	eID_MESURE_COEF_DILUTION,
	eID_MESURE_COEF_AJUSTEMENT,
	eID_MESURE_ALARM_DELTA,
	eID_LISTSTREAM_STATUS_SONDE,
	eID_LISTSTREAM_STATUS_CONCENTRATION,
    eID_MESURE_ALARM_DELTA2
};


typedef union {

	unsigned char value;

	struct {
		unsigned char bBit0:1;
		unsigned char bBit1:1;
		unsigned char bBit2:1;
		unsigned char bBit3:1;
		unsigned char bBit4:1;
		unsigned char bBit5:1;
		unsigned char bBit6:1;
		unsigned char bBit7:1;
	} bitfield;

} stBitField8;

typedef union {

	unsigned short value;

	struct {
		unsigned short bBit0:1;
		unsigned short bBit1:1;
		unsigned short bBit2:1;
		unsigned short bBit3:1;
		unsigned short bBit4:1;
		unsigned short bBit5:1;
		unsigned short bBit6:1;
		unsigned short bBit7:1;
		unsigned short bBit8:1;
		unsigned short bBit9:1;
		unsigned short bBit10:1;
		unsigned short bBit11:1;
		unsigned short bBit12:1;
		unsigned short bBit13:1;
		unsigned short bBit14:1;
		unsigned short bBit15:1;
	} bitfield;

} stBitField16;


#define SZ_TYPE_TXT		_T("TEXTE")
#define SZ_TYPE_FLOAT	_T("FLOAT")
#define SZ_TYPE_INT8	_T("INT08")
#define SZ_TYPE_INT16	_T("INT16")
#define SZ_TYPE_INT32	_T("INT32")

class CContext
{
public:
	CContext()
	{
		m_lNumVersion=NUM_LAST_VERSION;
		m_bAllData = FALSE;
		m_bModeInteger = FALSE;
		m_bSave = FALSE;
		m_hFile = NULL;
		m_pBuffStart = NULL;
		m_pBuffCurrent = NULL;
		m_iSize = 0;
		m_bForceByte = FALSE;
		m_bForceWord = FALSE;
	};
	CContext(BOOL bSave,FILE *hFile, BYTE* pBuffer,int iSize,BOOL bModeInteger,BOOL bAllData, long lNumVer = NUM_LAST_VERSION)
	{
		Reset(bSave,hFile, pBuffer,iSize,bModeInteger, bAllData, lNumVer);
	};
	void Reset(BOOL bSave,FILE *hFile, BYTE* pBuffer,int iSize,BOOL bModeInteger, BOOL bAllData, long lNumVer = NUM_LAST_VERSION)
	{
		m_lNumVersion=lNumVer;
		m_bAllData = bAllData;
		m_bModeInteger = bModeInteger;
		m_bSave = bSave;
		m_hFile = hFile;
		m_pBuffStart = pBuffer;
		m_pBuffCurrent = pBuffer;
		m_iSize = iSize;
		m_bForceByte = FALSE;
		m_bForceWord = FALSE;
	};
	int iGetCurrentSize(){return (int)(m_pBuffCurrent - m_pBuffStart);};
	void SetForceByte(BOOL bForceByte){ m_bForceByte = bForceByte;m_bForceWord = FALSE;};
	void SetForceWord(BOOL bForceWord){ m_bForceWord = bForceWord;m_bForceByte = FALSE;};
	BOOL bGetForceByte(){return m_bForceByte;};
	BOOL bGetForceWord(){return m_bForceWord;};
public:
	long m_lNumVersion;
	BOOL m_bAllData;
	BOOL m_bModeInteger;
	BOOL m_bSave;
	FILE *m_hFile;
	BYTE* m_pBuffStart;
	BYTE* m_pBuffCurrent;
	BOOL m_bForceByte;
	BOOL m_bForceWord;
	int m_iSize;
};


/*(@!*****************************************************************************************
* Nom     : CElem
* Role    : element de base 
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class CElemBase
{
public:
	CElemBase();
	virtual ~CElemBase();
	LPTSTR szGetLabel(){return m_pcLabel;};
	void SetLabel(LPCTSTR szText);
	void SetElemName(const QString& arg_elemName);
    QString getElemName()const;
	int iGetType(){return m_iType;};
	void SetType(long iType){m_iType = iType;};
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetTextVal(LPTSTR szVal){SetLabel(szVal);return TRUE;};
	virtual void GetVal(LPTSTR szVal, int iSizeMax=CONV_BUFFER_SIZE){szVal[0] = 0;};
	virtual BOOL bSetConfig(LPTSTR pszText);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);
	virtual void RemoveAll(){};

	void SetAutoDelete(BOOL bAutoDelete){m_bAutoDelete = bAutoDelete;};
	BOOL bIsAutoDelete(){return m_bAutoDelete;};

	BOOL bLoadSave(LPVOID lpData,long lDataSize,CContext &Context);
	BOOL bLoadSaveLabel(CContext &Context);
	BOOL bLoadSaveFloat(float &fData,CContext &Context);
	BOOL bLoadSaveInt8(BYTE &ucData,CContext &Context);
	BOOL bLoadSaveInt16(short &nData,CContext &Context);
	BOOL bLoadSaveUInt16(unsigned short &nData,CContext &Context);
	BOOL bLoadSaveInt32(long &iData,CContext &Context);
	BOOL bSetLabelLength(int iSize);
	long lGetLabelLength();

protected:
	TCHAR *m_pcLabel;
    QString m_elemName;
	short m_iLabelLength;
	long m_iType; //ID
	BOOL m_bAutoDelete;
	CRITICAL_SECTION m_hCriticalSection;
};

/*(@!*****************************************************************************************
* Nom     : CElemList
* Role    : Collection de valeur numerique
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class CElemList : public CElemBase
{
public:
	CElemList(int iNbrElem);
	virtual ~CElemList();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual void RemoveAll();
	virtual BOOL bSetConfig(LPTSTR pszText);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);
	CElemBase *pAdd(CElemBase* pElem);
	CElemBase *pGetAt(int iPos);
	BOOL bSetAt(int iPos,CElemBase *pElem);
	long iGetCount(){return m_iSize;};
	BOOL bAddAndRollText(LPCTSTR szText);

protected:
	CElemBase **m_ppElem;
	long m_iSize;
	long m_iSizeMax;
};

/*(@!*****************************************************************************************
* Nom     : CElemNbr
* Role    : element de base de gestion des nombres
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class CElemNbr : public CElemBase
{
public:
	CElemNbr();
	virtual ~CElemNbr();

public:
	CElemBase m_szUnit;
	CElemBase m_szFormat;

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR pszText);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

public:
};

/*(@!*****************************************************************************************
* Nom     : CElemFloat
* Role    : element de la base de type float
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemFloat : public CElemNbr
{
public:
	CElemFloat();
	virtual ~CElemFloat();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetTextVal(LPTSTR szVal){return bSetVal((float)_tcstod(szVal,NULL));};
	virtual void GetVal(LPTSTR szVal, int iSizeMax=CONV_BUFFER_SIZE){_stprintf(szVal,m_szFormat.szGetLabel(),m_fVal);};
	virtual BOOL bSetVal(float fVal){m_fVal = fVal;return TRUE;};
	virtual float fGetVal(){return m_fVal;};

	void operator+=(CElemFloat);
	void operator+=(float);
	void operator=(CElemFloat);
	void operator=(float);

protected:
	float m_fVal;
};

/*(@!*****************************************************************************************
* Nom     : CElemInt8
* Role    : element de la base de type int8
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemInt8 : public CElemNbr
{
public:
	CElemInt8();
	virtual ~CElemInt8();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetTextVal(LPTSTR szVal){return bSetVal((BYTE)lConvString2Long(szVal));};
	virtual void GetVal(LPTSTR szVal, int iSizeMax=CONV_BUFFER_SIZE){_stprintf(szVal,m_szFormat.szGetLabel(),m_ucVal);};

public:
	BOOL bSetVal(BYTE ucVal){m_ucVal = ucVal;return TRUE;};
	BOOL bIncVal(BYTE bInc){m_ucVal += bInc;return TRUE;};
	BYTE ucGetVal(){return m_ucVal;};
protected:
	BYTE m_ucVal;
};

/*(@!*****************************************************************************************
* Nom     : CElemInt16
* Role    : element de la base de type int16
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemInt16 : public CElemNbr
{
public:
	CElemInt16();
	virtual ~CElemInt16();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetTextVal(LPTSTR szVal){return bSetVal((short)lConvString2Long(szVal));};
	virtual void GetVal(LPTSTR szVal, int iSizeMax=CONV_BUFFER_SIZE){_stprintf(szVal,m_szFormat.szGetLabel(),m_nVal);};

public:
	BOOL bSetVal(short nVal){m_nVal = nVal;return TRUE;};
	BOOL bIncVal(short nInc){m_nVal+=nInc;return TRUE;};
	short nGetVal(){return m_nVal;};
protected:
	short m_nVal;
};

/*(@!*****************************************************************************************
* Nom     : CElemInt32
* Role    : element de la base de type int32
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemInt32 : public CElemNbr
{
public:
	CElemInt32();
	virtual ~CElemInt32();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetTextVal(LPTSTR szVal){return bSetVal(lConvString2Long(szVal));};
	virtual void GetVal(LPTSTR szVal, int iSizeMax=CONV_BUFFER_SIZE){_stprintf(szVal,m_szFormat.szGetLabel(),m_lVal);};

public:
	BOOL bSetVal(long lVal){m_lVal = lVal;return TRUE;};
	long lGetVal(){return m_lVal;};
protected:
	long m_lVal;
};

/*(@!*****************************************************************************************
* Nom     : CElemFieldBit8
* Role    : Collection de 8 bit
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class CListStream;
class  CElemFieldBit8 : public CElemList
{
public:
	CElemFieldBit8();
	virtual ~CElemFieldBit8();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR pszText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);
public:
};


/*(@!*****************************************************************************************
* Nom     : CElemFieldBit16
* Role    : Collection de 16 bit
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemFieldBit16 : public CElemList
{
public:
	CElemFieldBit16();
	virtual ~CElemFieldBit16();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
};

