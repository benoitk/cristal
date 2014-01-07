#pragma once

#define NUM_INTERFACE_CARTE_IO_MIN			1			// 1 a 6
#define NUM_INTERFACE_CARTE_IO_MAX			6			// 1 a 6
#define NUM_INTERFACE_CARTE_MESURE			10			
#define NUM_INTERFACE_SOCKET_IHM			20
#define NUM_INTERFACE_CARTE_JBUS_SLAVE		30			

class CThreadInterface;


class  CEnumInterface
{
public:
	CEnumInterface();
	virtual ~CEnumInterface();
	CThreadInterface *pGetSelectedInterface(int iNum);
	void SetExternalInterface(CThreadInterface *pSocketIHM,CThreadInterface *pCarteIO,CThreadInterface *pCarteMesure,CThreadInterface *pCarteJbusSlave);
	BOOL bSelectedInterfaceIsSocketIHM(CThreadInterface *pInterface){return (pInterface == m_pSocketIHM);};
public:
	CThreadInterface *m_pSocketIHM;
	CThreadInterface *m_pCarteIO;
	CThreadInterface *m_pCarteMesure;
	CThreadInterface *m_pCarteJbusSlave;
};


class  CThreadInterface : public CThread
{
// Operations
public:                 

	CThreadInterface();
	virtual ~CThreadInterface();

// Overrideables
public:
	virtual BOOL bWriteAndRead(long lExtraHeader,BYTE* pBufferWrite,long iSizeToWrite,BYTE* pBufferRead, long iSizeToRead,long iSizeToReadMax, long *piSizeRead,BOOL bByPass){return FALSE;};
	BOOL bReadConfig(LPCTSTR pszFileName);
	BOOL bWriteConfig(LPCTSTR pszFileName);
	BOOL bGetModeInteger(){return m_bModeInteger;};
	BYTE bGetNumInterface(){return m_bNumInterface;};
	BOOL bGetCanRead(){return m_bCanRead;};
	BOOL bGetCanWrite(){return m_bCanWrite;};
	BOOL bGetError(){return m_bError;};
	void SetAccess(BOOL bCanRead,BOOL bCanWrite);

protected:
	BOOL m_bModeInteger;
	BYTE m_bNumInterface;
	BOOL m_bCanRead;
	BOOL m_bCanWrite;
	long m_lNbrErrCom;
	int m_iNbrErrRead;
	int m_iNbrErrWrite;
	BOOL m_bError;

public:
	CEnumInterface m_ExternalInterface;
};

