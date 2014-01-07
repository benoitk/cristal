#pragma once

#include "CMesureModel.h"
#include <QVector>
#include <QString>

class CStreamModel
{
public:
	CStreamModel(void);
	
	void setNameStream(const QString& argNameStream){m_sNameStream = argNameStream;};
	void setNumStream(int argNumStream){m_iNumStream = argNumStream;};
	void setVectorMesure(const QVector<CMesureModel*>& argVectorMesure){m_vectorMesure = argVectorMesure;};

	QString getNameStream(){return m_sNameStream;};
	QVector<CMesureModel*> getVectorMesure()const{return m_vectorMesure;};

private:
	QString m_sNameStream;
	int m_iNumStream;
	QVector<CMesureModel*> m_vectorMesure;

};
