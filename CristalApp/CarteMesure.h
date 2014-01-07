#pragma once

////////////////////////////////////////////////////////////////////////////
// CSerialPort window
class CCarteMesure : public CSerialPort
{
public:
	CCarteMesure();
	virtual ~CCarteMesure();
	BOOL bReadConfig(LPCTSTR pszFileName,CListStream *pListStream);
	BOOL bWriteConfig(LPCTSTR pszFileName);

protected:
    //virtual DWORD RunThread();
    virtual void run();
};

/////////////////////////////////////////////////////////////////////////////
