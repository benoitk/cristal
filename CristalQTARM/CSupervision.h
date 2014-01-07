#ifndef CSUPERVISION
#define CSUPERVISION


#include <QHash>
#include <QString>
//#include <QSettings>

class CCarteMesure;
class CAnalyseur;
class CCarteIO;
class CSocketIHM;

#define NB_CARTE_IO_MAX 6
class CSupervision
{
public :
    enum eRemoteControl{
	    eREMOTE_DEFAULT	= 0,
	    eREMOTE_SAV	,			
	    eREMOTE_JBUS_SLAVE,			
	    eREMOTE_JBUS_MASTER	,			
    };

	CSupervision();
	
    void setCarteMesure(CCarteMesure* argpCarteMesure);
	void setAnalyseur(CAnalyseur* argpAnalyseur);
	void setCarteIO(CCarteIO* argpCarteIO);
	void setInterfaceIHM(CSocketIHM* argInterfaceIHM);

	int getNumRQTComJBUSMesure(const QString& sKey)const;
	int getNumRQTComJBUSIO(const QString& sKey)const;
	void addKeyOnMapRQTComJBUSMesure(const QString& sKey);
	void addKeyOnMapRQTComJBUSIO(const QString& sKey);
	QHash<QString, int> getHashRQTComJBUSMesure()const;
	QHash<QString, int> getHashRQTComJBUSIO()const;
	
	CCarteMesure* getCarteMesure();
	CCarteIO* getCarteIO();
	CAnalyseur* getAnalyseur();
	CSocketIHM* getInterfaceIHM()const;
	
	static float getFloatFromQByteArrayHex(const QByteArray& argByteArrayHex); 

private :

	CCarteIO* m_pIOCard;
	CCarteMesure* m_pMeasureCard;
	CAnalyseur* m_pAnalyseur;
	CSocketIHM* m_pInterfaceIHM;

	QHash<QString, int> m_hashRQTComJBUSMesure;
	QHash<QString, int> m_hashRQTComJBUSIO;
	int m_nNumRQTComJBUSMesure;
	int m_nNumRQTComJBUSIO;

    //QSettings* configIni;


};

#endif //CSUPERVISION