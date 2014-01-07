#include "CSupervision.h"

#include "header.h"
CSupervision::CSupervision()
{
	m_pMeasureCard = NULL;
	m_pAnalyseur = NULL;
	m_pIOCard = NULL;
	m_nNumRQTComJBUSIO = -1;
	m_nNumRQTComJBUSMesure = -1;
}


void CSupervision::setCarteIO(CCarteIO *argpCarteIO)
{
	
	m_pIOCard = argpCarteIO;

}

void CSupervision::setAnalyseur(CAnalyseur *argpAnalyseur)
{
	if(!m_pAnalyseur) m_pAnalyseur = argpAnalyseur;
}

void CSupervision::setCarteMesure(CCarteMesure *argpCarteMesure)
{
	m_pMeasureCard = argpCarteMesure;	
}

CAnalyseur* CSupervision::getAnalyseur()
{
	return (m_pAnalyseur)? m_pAnalyseur : NULL;
}

CCarteMesure* CSupervision::getCarteMesure()
{
	return (m_pMeasureCard)? m_pMeasureCard : NULL;
}

CCarteIO* CSupervision::getCarteIO()
{
	return (m_pIOCard)? m_pIOCard : NULL;
}

float CSupervision::getFloatFromQByteArrayHex(const QByteArray& argByteArrayHex)
{
	bool ok;
	int sign = 1;
	//QByteArray array("425AE78F");
	QByteArray byteArrayHex = QByteArray::number(argByteArrayHex.toLongLong(&ok,16),2); //convert hex to binary -you don't need this since your incoming data is binary
	if(byteArrayHex.length()==32) {
	if(byteArrayHex.at(0)=='1') sign =-1; // if bit 0 is 1 number is negative
	byteArrayHex.remove(0,1); // remove sign bit
	}
	QByteArray fraction =byteArrayHex.right(23); //get the fractional part
	double mantissa = 0;
	for(int i=0;i<fraction.length();i++) // iterate through the array to claculate the fraction as a decimal.
	if(fraction.at(i)=='1') mantissa += 1.0/(pow(2,i+1));
	int exponent = byteArrayHex.left(byteArrayHex.length()-23).toLongLong(&ok,2)-127; //claculate the exponent
	float fResult = sign*pow(2,exponent)*(mantissa+1.0);
	return fResult;
}
void CSupervision::setInterfaceIHM(CSocketIHM* argInterfaceIHM)
{
    argInterfaceIHM=m_pInterfaceIHM;
}
int CSupervision::getNumRQTComJBUSMesure(const QString& sKey)const
{
    return m_hashRQTComJBUSMesure.value(sKey);
}
int CSupervision::getNumRQTComJBUSIO(const QString& sKey)const
{
    return m_hashRQTComJBUSIO.value(sKey);
}
void CSupervision::addKeyOnMapRQTComJBUSMesure(const QString& sKey)
{
    m_hashRQTComJBUSMesure.insert(sKey, ++m_nNumRQTComJBUSMesure);
}
void CSupervision::addKeyOnMapRQTComJBUSIO(const QString& sKey)
{
    m_hashRQTComJBUSIO.insert(sKey, ++m_nNumRQTComJBUSIO);
}
QHash<QString, int> CSupervision::getHashRQTComJBUSMesure()const
{
    return m_hashRQTComJBUSMesure; 
}
QHash<QString, int> CSupervision::getHashRQTComJBUSIO()const
{
    return m_hashRQTComJBUSIO; 
}
CSocketIHM* CSupervision::getInterfaceIHM()const
{
    return m_pInterfaceIHM;
}

