#pragma once

class CListStream;
class CSerialPort;
class CStream;

/*(@!*****************************************************************************************
* Nom     : CElemCycleStep
* Role    : definition du traitement JBUS d'un pas sur la carte mesure
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
#define NBR_EXCHANGE_JBUS_MAX		256
class CElemCycleStep : public CElemBase
{
public:
	CElemCycleStep();
	virtual ~CElemCycleStep();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual void RemoveAll();

public:
	BOOL bReadConfig(LPTSTR pszRub, LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bWriteConfig(LPTSTR pszRub,LPCTSTR pszFileName);
	BOOL bReadConfigExchangeJbus(LPTSTR pszRub, LPTSTR pszKeyRQ,LPTSTR pszKeyRP,LPCTSTR pszFileName,CElemList *pListExchange,CListStream *pListStream);
	BOOL bWriteConfigExchangeJbus(LPTSTR pszRub, LPTSTR pszKeyRQ,LPTSTR pszKeyRP, int iPos ,LPCTSTR pszFileName,CElemList *pListExchange);
	BOOL bExecuteBegin(BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface);
	BOOL bExecuteEnd(BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface);
	BOOL bExecuteRealTime(BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface);
	BOOL bFindRqAndExecuteFromIHM(long lExtraHeader,BOOL bCanRead, BOOL bCanWrite,BYTE *pBufferIn,long lSizeIn,BYTE *pBufferOut, long *plSizeOut,long lSizeOutMax,CEnumInterface &EnumInterface);
	BOOL bExecute(CElemInt8 *pCmdRun,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle,CEnumInterface &EnumInterface);

public:
	BOOL bExecuteListExchange(CElemList *pListExchange, BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface);
	BOOL bExecuteNumExchange(int iNum,CElemList *pListExchange, BOOL bCanRead, BOOL bCanWrite,CEnumInterface &EnumInterface);

public:
	// ces liste contiennent des CElemExchangeJbus
	CElemInt16 m_Step;
	CElemList m_ListExchangeBegin;
	CElemList m_ListExchangeEnd;
	CElemList m_ListExchangeRealTime;
};


/*(@!*****************************************************************************************
* Nom     : CElemCycle
* Role    : definition du traitement d'un cycle
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
#define NBR_CYCLE_STEP_MAX					1024

class CElemCycle : public CElemList
{
public:
	CElemCycle();
	virtual ~CElemCycle();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual void RemoveAll();
	virtual BOOL bExecute(CElemInt8 *pCmdRun,CElemInt8 *pCmdStopEndCycle,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle,CEnumInterface &EnumInterface, CStream* argpStream, CElemInt8* argNumCurrentStream);
	
	BOOL bWaitForNextStep(short nNextTime,CElemInt8 *pCmdRun,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pTimeCycle);
	BOOL bWaitForNextTime(short nNextTime,CElemInt8 *pCmdRun,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pTimeCycle);
public:
	BOOL bReadConfig(LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bWriteConfig(LPCTSTR pszFileName);
	CElemCycleStep *pGetCurrentStep();
	void SetCurrentStep(CElemCycleStep *pStep);
public:
	CElemInt16 m_Duration;
	// liste contient des CElemCycleStep
	CElemCycleStep m_ElemCycleStepStop;
	//CRITICAL_SECTION  m_hCriticalSection;

public:
	static CElemCycleStep m_CurrentStep;
};


/*(@!*****************************************************************************************
* Nom     : CElemCycleZero
* Role    : definition du traitement d'un cycle de zero
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class CElemCycleZero : public CElemCycle
{
public:
	CElemCycleZero();
	virtual ~CElemCycleZero();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bExecute(CElemInt8 *pCmdRun,CElemInt8 *pCmdStopEndCycle,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle,CEnumInterface &EnumInterfacen, CStream* argpStream, CElemInt8* argNumCurrentStream);

public:
	BOOL bReadConfig(LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bWriteConfig(LPCTSTR pszFileName);
};

/*(@!*****************************************************************************************
* Nom     : CElemCycleCalib
* Role    : definition du traitement d'un cycle de calibration
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class CElemCycleCalib : public CElemCycleZero
{
public:
	CElemCycleCalib();
	virtual ~CElemCycleCalib();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bExecute(CElemInt8 *pCmdRun,CElemInt8 *pCmdStopEndCycle,CElemInt8 *pCmdPause,CElemInt16 *pCmdJumpStep,CElemInt16 *pStatusRealTime,CElemInt16 *pTimeCycle,CEnumInterface &EnumInterface, CStream* argpStream, CElemInt8* argNumCurrentStream);

public:
	BOOL bReadConfig(LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bWriteConfig(LPCTSTR pszFileName);
};

/*(@!*****************************************************************************************
* Nom     : CElemCycleCalib
* Role    : definition du traitement d'un cycle de calibration
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class CElemCycleCleanup : public CElemCycle
{
public:
	CElemCycleCleanup();
	virtual ~CElemCycleCleanup();

public:
	BOOL bReadConfig(LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bWriteConfig(LPCTSTR pszFileName);
};




