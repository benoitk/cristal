#pragma once


class CListStream;
			 
extern  WORD wCalculCRC16(BYTE* pucBuffer, long lSize);
/*(@!*****************************************************************************************
* Nom     : CElemTrameJbus
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
#define NBR_PARAM_MAX		64
class  CElemTrameJbus : public CElemBase
{
public:
	CElemTrameJbus();
	virtual ~CElemTrameJbus();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos, CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);
	BOOL bUpdateData(BYTE *pBuffer,int iSize,BOOL bModeInteger);

	BOOL bSerializeCRC16(BYTE* pucBuffer, long lSize,CContext &Context);
	BOOL bAccessAllowed(BOOL bCanRead,BOOL bCanWrite);
	BYTE ucGetNumDest(){return m_NumDest.ucGetVal();};
protected:
	CElemInt8 m_NumDest;
	CElemInt8 m_CodeFct;
	CElemInt16 m_CRC16;
	CElemList m_ListParams;
};

/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 1 et 2
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemTrameJbusReadBitsRQ_1_2: public CElemTrameJbus
{
public:
	CElemTrameJbusReadBitsRQ_1_2();
	virtual ~CElemTrameJbusReadBitsRQ_1_2();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_StartAddr;
	CElemInt16 m_NbrBits;
};

class  CElemTrameJbusReadBitsRP_1_2: public CElemTrameJbus
{
public:
	CElemTrameJbusReadBitsRP_1_2();
	virtual ~CElemTrameJbusReadBitsRP_1_2();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt8 m_NbrBytes;
};

/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 3 et 4
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemTrameJbusReadWordsRQ_3_4: public CElemTrameJbus
{
public:
	CElemTrameJbusReadWordsRQ_3_4();
	virtual ~CElemTrameJbusReadWordsRQ_3_4();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_StartAddr;
	CElemInt16 m_NbrWords;
};

class  CElemTrameJbusReadWordsRP_3_4: public CElemTrameJbus
{
public:
	CElemTrameJbusReadWordsRP_3_4();
	virtual ~CElemTrameJbusReadWordsRP_3_4();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt8 m_NbrBytes;
};

/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 5
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemTrameJbusWriteBit_5: public CElemTrameJbus
{
public:
	CElemTrameJbusWriteBit_5();
	virtual ~CElemTrameJbusWriteBit_5();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_StartAddr;
};

/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 6
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemTrameJbusWriteWord_6: public CElemTrameJbus
{
public:
	CElemTrameJbusWriteWord_6();
	virtual ~CElemTrameJbusWriteWord_6();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_StartAddr;
};

/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 15
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemTrameJbusWriteBitsRQ_15: public CElemTrameJbus
{
public:
	CElemTrameJbusWriteBitsRQ_15();
	virtual ~CElemTrameJbusWriteBitsRQ_15();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_StartAddr;
	CElemInt16 m_NbrBits;
	CElemInt8 m_NbrBytes;
};

class  CElemTrameJbusWriteBitsRP_15: public CElemTrameJbus
{
public:
	CElemTrameJbusWriteBitsRP_15();
	virtual ~CElemTrameJbusWriteBitsRP_15();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_StartAddr;
	CElemInt16 m_NbrBits;
};

/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 16
* Role    : definition d'une trame JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemTrameJbusWriteWordsRQ_16: public CElemTrameJbus
{
public:
	CElemTrameJbusWriteWordsRQ_16();
	virtual ~CElemTrameJbusWriteWordsRQ_16();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_StartAddr;
	CElemInt16 m_NbrWords;
	CElemInt8 m_NbrBytes;
};

class  CElemTrameJbusWriteWordsRP_16: public CElemTrameJbus
{
public:
	CElemTrameJbusWriteWordsRP_16();
	virtual ~CElemTrameJbusWriteWordsRP_16();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_StartAddr;
	CElemInt16 m_NbrWords;
};


/*(@!*****************************************************************************************
* Nom     : Fonction JBUS 20
* Role    : definition d'une trame JBUS socket
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemTrameJbusSocket_20: public CElemTrameJbus
{
public:
	CElemTrameJbusSocket_20();
	virtual ~CElemTrameJbusSocket_20();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(LPTSTR pszText, int iSizeMax);

protected:
	CElemInt16 m_NbrParams;
};

/*(@!*****************************************************************************************
* Nom     : CElemExchangeJbus
* Role    : definition d'un echange JBUS
* --------------------------------------------------------------------------------------------
* Contraintes         : sans objet
* Donnees en entree   : sans objet
* Donnees en sortie   : sans objet
* --------------------------------------------------------------------------------------------
* Pseudo code		  : sans objet
*
*****************************************************************************************@!)*/
class  CElemExchangeJbus : public CElemBase
{
public:
	CElemExchangeJbus();
	virtual ~CElemExchangeJbus();

public:
	virtual BOOL bSerialize(CContext &Context);
	virtual int iGetStreamSize(CContext &Context);
	virtual BOOL bSetConfig(BOOL bIsRQ, LPTSTR szText,int &iCurrentPos,CListStream *pListStream);
	virtual LPTSTR szGetConfig(BOOL bIsRQ, LPTSTR pszText, int iSizeMax);
	virtual void RemoveAll();

protected:
	int iGetNumFunction(LPTSTR pszText);

public:
	CElemTrameJbus *m_pTrameJbusRQ;
	CElemTrameJbus *m_pTrameJbusRP;
};








