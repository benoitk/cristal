#ifndef CWIN_STREAM_MODEL
#define CWIN_STREAM_MODEL

#include <QObject>
#include <QString>
#include <QList>
#include <QVector>
class CWinStreamView;
class CSupervision;
class CStreamModel;
class CValue
{
public:
	CValue(QString arg_sValue, QString arg_sUnit, QString arg_sLabel, QString arg_sKey, QString arg_sName, int arg_numStream, int arg_numMeasure)
	{
		m_numStream = arg_numStream;
		m_numMeasure = arg_numMeasure;
		m_sValue = arg_sValue;
		m_sUnit = arg_sUnit;
		m_sLabel = arg_sLabel;
		m_sKey = arg_sKey;
		m_sName = arg_sName;
	};
	
	QString getValue()const{return m_sValue;};
	QString getUnit()const{return m_sUnit;};
	QString getLabel()const{return m_sLabel;};
	QString getKey()const{return m_sKey;};
	QString getName()const{return m_sName;};
	int getNumStream()const{return m_numStream;};
	int getNumMeasure()const{return m_numMeasure;};
	void setValue(const QString& arg_sValue){m_sValue = arg_sValue;};

private:
	int m_numStream;
	int m_numMeasure;
	QString m_sValue;
	QString m_sUnit;
	QString m_sLabel;
	QString m_sKey;
	QString m_sName;
};
class CWinStreamModel: public QObject
{
	Q_OBJECT
public:
	CWinStreamModel(CSupervision* argoSupervision, CWinStreamView* argoView);
	QVector<CStreamModel*> getVectorStream()const{return m_vectorStream;}; 
	QList<CValue*>::iterator getValuesIteratorBegin(){return m_listValues.begin();};
	QList<CValue*>::iterator getValuesIteratorEnd(){return m_listValues.end();};
    QList<QString> getListKeyValues(int arg_numStream, int arg_numMeasure)const{return m_listData.at(arg_numStream).at(arg_numMeasure);};
    int getNbStreamValue(int arg_numStream, int arg_numMeasure)const{return m_listData.at(arg_numStream).at(arg_numMeasure).count();};
    int getNbMeasure() const;
    //QList<QString> getValuesIteratorEnd(int numStream)const{return m_listData.at(numStream).end();};
    bool getStreamIsActive(int arg_numStream)const;
    bool getStreamStatus(int arg_numStream)const;
    bool getStreamStatusSeuil1(int arg_numStream)const;
    bool getStreamStatusSeuil2(int arg_numStream)const;
    bool getStreamStatusWaterFailure(int arg_numStream)const;
    bool getStreamStatusCycleRunning(int arg_numStream)const;
    
    QString getValue(int arg_numStream, int arg_numMeasure, int arg_numValue)const;
    QString getValueLbl(int arg_numStream, int arg_numMeasure, int arg_numValue)const;
    QString getValueUnit(int arg_numStream, int arg_numMeasure, int arg_numValue)const;

	int getNombreValues(int arg_numStream, int arg_numMeasure)const{return m_listData.at(arg_numStream).at(arg_numMeasure).count();};

	void setValue(int arg_numStream, int arg_numMeasure, int arg_index, const QString& arg_sValue);
    void setVoieActive(int arg_numStream, bool arg_bActive);
	void updateDataFromSupervision();
    
    void updateOffsetMesure(int arg_numStream, int arg_numMeasure);

public slots:

private:
	//Coté supervision connexion aux données
	
	QList<QList<QList<QString>>> m_listData;
	//coté model
	QVector<CStreamModel*> m_vectorStream; 
	QList<CValue*> m_listValues;


	CWinStreamView* m_pView;
    CSupervision* m_pSupervision;

};



#endif