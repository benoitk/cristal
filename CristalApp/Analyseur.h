#pragma once
#include "Network.h"
class CAnalyseur : public CListStream
{
public:
	int getIndexSeq()const{return m_indexSeqence;};
	int getTimeElapse()const{return m_iTimeElapse;};
	CAnalyseur();
	virtual ~CAnalyseur();


protected:
    //virtual DWORD RunThread();
    virtual void run();

private :
	int m_indexSeqence;
	int m_iTimeElapse;
};

			 




