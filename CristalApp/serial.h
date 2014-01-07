#pragma once

class CListStream;
class CElemList;

#define TIME_OUT_READ_RS232			500
////////////////////////////////////////////////////////////////////////////
// CSerialPort window
class CSerialPort : public CThreadInterface
{
public:
	CSerialPort();
	virtual ~CSerialPort();
	BOOL bReadConfig(LPCTSTR pszFileName);
	BOOL bWriteConfig(LPCTSTR pszFileName);

public:
	virtual BOOL bWrite (BYTE* lpData,long lSizeTotal);
	virtual BOOL bRead(BYTE* lpData,long lSizeDataMax,long *plNbrLu,BOOL bByPass);
	virtual BOOL bWriteAndRead(long lExtraHeader,BYTE* pBufferWrite,long iSizeToWrite,BYTE* pBufferRead, long iSizeToRead,long iSizeToReadMax, long *piSizeRead,BOOL bByPass);
	virtual BOOL bAddExchangeJbus(LPTSTR pszRQ,LPTSTR pszRP,CListStream *pListStream);
	virtual void Stop();
	virtual CElemList* getListExchange(){return m_pListExchange;};
//////////////// FONCTIONS
protected:
    //virtual DWORD RunThread();
	virtual void run();
    virtual long lDispatchTrame(BYTE* lpData,long lSizeTotal);
	BOOL bOpen();
	void Close();
protected:
	// Membres
	DCB m_DCB;
	HANDLE m_hTTY;
	long m_lSizeDataMax;
	BYTE *m_pRxBuffer;
	long m_lOffsetBuffer;
	short m_nNumPort;
	CElemList *m_pListExchange;
};

/////////////////////////////////////////////////////////////////////////////
