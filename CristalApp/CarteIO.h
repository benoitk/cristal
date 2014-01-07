#pragma once

////////////////////////////////////////////////////////////////////////////
// CSerialPort window
class CCarteIO : public CSerialPort
{
public:
	CCarteIO();
	virtual ~CCarteIO();
	virtual void Stop();
	BOOL bReadConfig(LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bWriteConfig(LPCTSTR pszFileName);
protected:
    //virtual DWORD RunThread();
    virtual void run();
public:
	CElemCycleStep m_ElemCycleStep;
protected:
	DWORD m_dwDelay;
};

/////////////////////////////////////////////////////////////////////////////
