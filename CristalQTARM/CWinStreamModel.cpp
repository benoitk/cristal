#include "CWinStreamModel.h"
#include "CWinStreamView.h"
#include "CSupervision.h"
#include "CMesureModel.h"
#include "CStreamModel.h"
#include "CMesureModel.h"

#include "header_qt.h"

CWinStreamModel::CWinStreamModel(CSupervision* argoSupervision, CWinStreamView* argoView)
{
	CMesureModel* pMesureModel;
    CStreamModel* pStreamModel;

	QVector<CMesureModel*>* vectorMesure; 
	m_pSupervision = argoSupervision;
    
    int nbStream = m_pSupervision->getAnalyseur()->iGetNbrStream();
    
	//A remplacer par la lecture d'un fichier de conf
	    QList<QString> listValuesKey; QList<QString> listValuesNames;

    for(int i=0; i<nbStream; ++i)
    {
        QList<QList<QString>> listMesure;
        for(int j=0; j<m_pSupervision->getAnalyseur()->pGetAt(i)->iGetNbrMesure(); ++j)
        {
	        QList<QString> listValuesKey; 
         //   listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060c");//listValuesNames.append("m_CalibZeroAir");
	        //listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0622");//listValuesNames.append("m_Delta");

    #if defined(SONDE) && defined(PH) && defined(MULTI_MEASURE)
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0601");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0602");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0603");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0606");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0607");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0608");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0609");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060a");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061a");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061b");

	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061f");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0417");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0618");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061d");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0619");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0620");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060b");
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0623");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060c");
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0622");

	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061e");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06c9");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06ca");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0621");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cb");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cc");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06ce");
	        
    #elif defined(SONDE)
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0601");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0602");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0603");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0606");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0607");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0608");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0609");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061f");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061a");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060a");//listValuesNames.append("m_AnalogPlage");

	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0417");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0618");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061d");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0619");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0620");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061e");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06db");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0621");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06ce");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cf");//listValuesNames.append("m_AnalogPlage");

	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06c9");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06ca");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cb");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cc");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cd");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060b");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0623");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061b");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060c");//listValuesNames.append("m_AnalogPlage");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061c");//listValuesNames.append("m_AnalogPlage");
    #elif defined(COULEUR)
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0601");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0602");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0603");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0606");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0607");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0608");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0609");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060a");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061a");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06da");

	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0417");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06c9");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06ca");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0618");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061d");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0619");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060b");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0620");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0621");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061b");

            /*listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cf");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06d0");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cc");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06cd");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06d8");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06d3");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"06d9");*/
    #elif defined(KMNO4)
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0417");
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060c");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0622");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0619");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0623");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0620");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0621");
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060b");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060a");
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0601");
            

	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0602");
  	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0603");
  	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0606");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0607");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0608");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0609");
	       /* listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061a");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061b");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0618");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061d");*/

#else //COLO
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0601");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0602");
    #ifdef RES_640_480
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0603");
    #endif
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0606");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0607");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0608");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0609");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060a");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061a");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061b");

            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060b");
            listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"060c");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0417");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0618");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061d");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0619");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0620");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0621");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"061f");
	        listValuesKey.append("0x0" + QString::number(i) +"0"+ QString::number(j) +"0622");
    	    
    #endif
            listMesure.append(listValuesKey);
 
        }
        m_listData.append(listMesure);
    }
	//listValuesKey.append("0x00ff063b");listValuesNames.append("m_WaterFailureSetPoint");

	/*listValuesKey.append("0x0000060b");listValuesNames.append("m_ValMin");
	listValuesKey.append("0x0000060a");listValuesNames.append("m_CalibCoeff");
	listValuesKey.append("0x00000602");listValuesNames.append("m_Threshold1");
	listValuesKey.append("0x00000603");listValuesNames.append("m_Threshold2");
	listValuesKey.append("0x00000607");listValuesNames.append("m_ValMax");
	listValuesKey.append("0x00000606");listValuesNames.append("m_ValMin");
	listValuesKey.append("0x00000608");listValuesNames.append("m_AnalogPlage");
	listValuesKey.append("0x00000609");listValuesNames.append("m_AnalogZero");
	listValuesKey.append("0x00000619");listValuesNames.append("m_AbsorbanceValue");
	listValuesKey.append("0x00000622");listValuesNames.append("m_Delta");*/

	/*listValuesKey.append("0x00000603");listValuesNames.append("m_Threshold2");
	listValuesKey.append("0x00000607");listValuesNames.append("m_ValMax");
	listValuesKey.append("0x00000606");listValuesNames.append("m_ValMin");
	listValuesKey.append("0x00000608");listValuesNames.append("m_AnalogZero");
	listValuesKey.append("0x00000619");listValuesNames.append("m_AbsorbanceValue");
	listValuesKey.append("0x00000622");listValuesNames.append("m_Delta");*/
	//listValuesKey.append("0x00000601");

	
	//Fin à remplancer

	//Init des voies et mesures  (multivoie, applicable pour le cristal et cristallite)
	for(int i=0; i<m_pSupervision->getAnalyseur()->iGetNbrStream()&&i<1; ++i)
	{
		pStreamModel = new CStreamModel();
		vectorMesure = new QVector<CMesureModel*>();
		int test = m_pSupervision->getAnalyseur()->pGetAt(i)->iGetNbrMesure();
		for(int j=0; j<m_pSupervision->getAnalyseur()->pGetAt(i)->iGetNbrMesure(); ++j)
		{
			pMesureModel = new CMesureModel();
			pMesureModel->setName(QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(j)->m_Val.szGetLabel()
																	, m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(j)->m_Val.lGetLabelLength()));
			pMesureModel->setUnite(QString::fromUtf16(( const ushort *)m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(j)->m_Val.m_szUnit.szGetLabel()
																	 , m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(j)->m_Val.m_szUnit.lGetLabelLength()));
			//pMesureModel->setValeur(argoSupervision->getAnalyseur()->pGetAt(i)->pGetAt(j)->m_Val.fGetVal());
			pMesureModel->setpMesure(m_pSupervision->getAnalyseur()->pGetAt(i)->pGetAt(j));
			vectorMesure->append(pMesureModel);
			int indexListValueName = 0;
			foreach(QString sKey, listValuesKey)
			{
				//qDebug() << "foreach(QString sKey, listValuesKey) " << pMesureModel->getVarMesureValeur(sKey) << " key " << sKey;
				//qDebug() << "foreach(QString sKey, listValuesKey) " << pMesureModel->getVarMesureUnit(sKey) << " key " << sKey;
				//qDebug() << "foreach(QString sKey, listValuesKey) " << pMesureModel->getVarMesureLbl(sKey) << " key " << sKey;
				m_listValues.append(new CValue( pMesureModel->getVarMesureValeur(sKey)
										  , pMesureModel->getVarMesureUnit(sKey)
										  , pMesureModel->getVarMesureLbl(sKey)
										  , sKey, listValuesNames[indexListValueName], i, j));
				/*qDebug() << "foreach(QString sKey, listValuesKey) unit" << m_listValues.last()->getUnit();
				qDebug() << "foreach(QString sKey, listValuesKey) lbl" << m_listValues.last()->getLabel();
				qDebug() << "foreach(QString sKey, listValuesKey) value" << m_listValues.last()->getValue();
				qDebug() << "foreach(QString sKey, listValuesKey) key" << m_listValues.last()->getKey();
				qDebug() << "foreach(QString sKey, listValuesKey) Name" << m_listValues.last()->getName();*/
				++indexListValueName;
			}
		}

		pStreamModel->setNumStream(i);	
		pStreamModel->setVectorMesure(*vectorMesure);
		m_vectorStream.append(pStreamModel);
	}

//	getDataFromSupervision();
}
int CWinStreamModel::getNbMeasure() const
{
    return m_pSupervision->getAnalyseur()->pGetAt(0)->iGetNbrMesure();
}
bool CWinStreamModel::getStreamIsActive(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
        return m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_Active.ucGetVal();
    else
        return false;
}
bool CWinStreamModel::getStreamStatus(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
        return !m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_StatusFailure.ucGetVal();
    else
        return false;
}
bool CWinStreamModel::getStreamStatusSeuil1(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
        return !m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_StatusThreshold1.ucGetVal();
    else
        return false;
}
bool CWinStreamModel::getStreamStatusSeuil2(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
        return !m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(0)->m_StatusThreshold2.ucGetVal();
    else
        return false;
}
bool CWinStreamModel::getStreamStatusWaterFailure(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
        return !m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_StatusWaterFailure.ucGetVal();
    else
        return false;
}
bool CWinStreamModel::getStreamStatusCycleRunning(int arg_numStream)const
{
    if(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream))
        return m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_IsRunning.ucGetVal();
    else
        return false;
}
void CWinStreamModel::setVoieActive(int arg_numStream, bool arg_bActive)
{
    m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->m_Active.bSetVal(arg_bActive);
}

void CWinStreamModel::setValue(int arg_numStream, int arg_numMeasure, int arg_index, const QString& arg_sValue)
{
   
	//Base mis à 0 pour utilisé la convention du C soit dansnotre cas chaine qui commence par 0x convertion en hex
	long lIdVar = m_listData.at(arg_numStream).at(arg_numMeasure).at(arg_index).toLong(0,16);
	int iTypeVar = NUM_TYPE(lIdVar);
    QString sSectionName = "CStream" +  QString::number(NUM_VOIE(lIdVar)) 
                         + "_CMesure" + QString::number(NUM_MESURE(lIdVar));
	//qDebug() << "m_mapIdRefVar.contains(lIdVar) " << m_mapIdRefVar.contains(lIdVar);
	if(lIdVar!=0)
	{
        CElemBase* elem = m_pSupervision->getAnalyseur()->pFindElemFromID(lIdVar);
		qDebug() << "iTypeVar "<< iTypeVar ;
		switch(iTypeVar)
		{
			case eTYPE_INT8:
				((CElemInt8*)elem)->bSetVal((BYTE)arg_sValue.toShort(0, 10));
				break;
			case eTYPE_INT16:
				((CElemInt16*)elem)->bSetVal(arg_sValue.toInt(0, 10));
				break;
			case eTYPE_FLOAT:
				((CElemFloat*)elem)->bSetVal(arg_sValue.toFloat());
				break;
		}
        CMesureModel::writeElemConfigIni((WCHAR *) sSectionName.utf16()
							, (WCHAR *)elem->getElemName().utf16()
							, elem);
		/*TRACE_LOG_MSG((WCHAR *)argsObjectName.utf16());
		TRACE_LOG_MSG(m_mapIdRefVar.value(lIdVar)->szGetConfig(szText3,MAX_PATH));*/
	}	

	/*qDebug() << "m_listValues.at(arg_index)->getNumStream() " << m_listValues.at(arg_index)->getNumStream();
	CStreamModel* pStreamModel = m_vectorStream.at(m_listValues.at(arg_index)->getNumStream());
	qDebug() << "m_listValues.at(arg_index)->getNumMeasure() " << m_listValues.at(arg_index)->getNumMeasure();

	CMesureModel* pMesureModel = pStreamModel->getVectorMesure().at(m_listValues.at(arg_index)->getNumMeasure());
	qDebug() << "m_listValues.at(arg_index)->getKey() " << m_listValues.at(arg_index)->getKey();
	pMesureModel->setVarMesureValeur(m_listValues.at(arg_index)->getName(), m_listValues.at(arg_index)->getKey(), arg_sValue);
	qDebug() << "arg_sValue " << arg_sValue;*/

}

void CWinStreamModel::updateDataFromSupervision()
{
	CValue* temp;
	foreach(temp, m_listValues)
	{
		CStreamModel* pStreamModel = m_vectorStream.at(temp->getNumStream());
		CMesureModel* pMesureModel = pStreamModel->getVectorMesure().at(temp->getNumMeasure());
		temp->setValue(pMesureModel->getVarMesureValeur(temp->getKey()));
	}
}
//Applique l'offset de mesure pour quelle soit utilisable par la linéaristion
// Exemple pour le silice mesure brut à 10mg, client veut retrancher 5 à la mesure du à la présence de sillice dans les réactifs 
void CWinStreamModel::updateOffsetMesure(int arg_numStream, int arg_numMeasure)
{
#ifdef COULEUR
    float iOffset = m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_ZeroStandard.fGetVal();

    float resultat = iOffset * 0.0019;
#elif defined(SILICE) //(Silice)
    float iOffset = m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibZeroAir.fGetVal();

    float resultat = (iOffset * 0.016)/25;
#else
    float x = ((CElemFloat*)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_ListCoeffLinear.pGetAt(9))->fGetVal();
    float y = ((CElemFloat*)m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_ListCoeffLinear.pGetAt(19))->fGetVal();
    float iOffset = m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibZeroAir.fGetVal();
    qDebug() << "x:" << x << " y:" << y << " iOffset:" << iOffset;
    float resultat = (iOffset * x)/y;
    qDebug() << "resultat1:" << resultat; 
    resultat = m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibZeroWater.fGetVal()-resultat;
    qDebug() << "resultat2:" << resultat; 
#endif
    m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibZeroWater.bSetVal(resultat);
   
    QString section = QString("CStream")+ QString::number(arg_numStream)+ QString("_CMesure")+QString::number(arg_numMeasure) ;
    CMesureModel::writeElemConfigIni((WCHAR *)section.utf16()
                                  , _T("m_CalibZeroWater")
                                  , &m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_CalibZeroWater);
    
}
QString CWinStreamModel::getValue(int arg_numStream, int arg_numMeasure, int arg_numValue)const
{
    QString sKey = m_listData.at(arg_numStream).at(arg_numMeasure).at(arg_numValue);
    CElemBase* elem = m_pSupervision->getAnalyseur()->pFindElemFromID(sKey.toLong(0,16));
    if(elem)
        switch(NUM_TYPE(elem->iGetType()))
        {
            case eTYPE_FLOAT: return QString::number(((CElemFloat*)elem)->fGetVal(), 'f', 5); 
            case eTYPE_INT16: return QString::number(((CElemInt16*)elem)->nGetVal()); 
            case eTYPE_INT32: return QString::number(((CElemInt32*)elem)->lGetVal()); 
            case eTYPE_INT8: return QString::number(((CElemInt8*)elem)->ucGetVal()); 
                                 
            default: return "NaN";
        }
    else
        return "NaN";
}
QString CWinStreamModel::getValueLbl(int arg_numStream, int arg_numMeasure, int arg_numValue)const
{
    //CSupervision* sup;
    QString sKey = m_listData.at(arg_numStream).at(arg_numMeasure).at(arg_numValue);
   // qDebug() << " sKey :" <<  QString::number(sKey.toLong(0,16));
    CElemBase* elem = m_pSupervision->getAnalyseur()->pFindElemFromID(sKey.toLong(0,16));
    if(elem)
        return QString::fromUtf16(( const ushort *)elem->szGetLabel()
	    										 , elem->lGetLabelLength());
    else
        return "NaN";

}
QString CWinStreamModel::getValueUnit(int arg_numStream, int arg_numMeasure, int arg_numValue)const
{

     QString sKey = m_listData.at(arg_numStream).at(arg_numMeasure).at(arg_numValue);
    CElemBase* elem = m_pSupervision->getAnalyseur()->pFindElemFromID(sKey.toLong(0,16));
    if(elem)
        switch(NUM_TYPE(elem->iGetType()))
        {
            case eTYPE_FLOAT: return QString::fromUtf16(( const ushort *)((CElemFloat*)elem)->m_szUnit.szGetLabel()
                                                                        ,((CElemFloat*)elem)->m_szUnit.lGetLabelLength()); 
            case eTYPE_INT8: return QString::fromUtf16(( const ushort *)((CElemInt8*)elem)->m_szUnit.szGetLabel()
                                                                        ,((CElemInt8*)elem)->m_szUnit.lGetLabelLength()); 
            case eTYPE_INT16: return QString::fromUtf16(( const ushort *)((CElemInt16*)elem)->m_szUnit.szGetLabel()
                                                                        ,((CElemInt16*)elem)->m_szUnit.lGetLabelLength()); 
            case eTYPE_INT32: return QString::fromUtf16(( const ushort *)((CElemInt32*)elem)->m_szUnit.szGetLabel()
                                                                        ,((CElemInt32*)elem)->m_szUnit.lGetLabelLength()); 
                                                     
            default: return "NaN";
        }
    else
        return "NaN";
}

