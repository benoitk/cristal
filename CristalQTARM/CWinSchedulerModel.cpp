#include "CWinSchedulerModel.h"
#include "CWinSchedulerView.h"
#include "CSupervision.h"
#include "CMesureModel.h"

#include "Analyseur.h"

#include <QFile>
#include <QTextCodec>

CWinSchedulerModel::CWinSchedulerModel(CSupervision* argpSupervision, CWinSchedulerView* argpView)
{
	m_timer = NULL;
	m_pSupervision = argpSupervision;
	m_pView = argpView;
}


void CWinSchedulerModel::setConnexion()
{
	//PAr trigger ou timer ?
	m_timer = new QTimer(this);
	m_timer->setInterval(1000);
//	connect(m_timer, SIGNAL(timeout()), this, SLOT(getDataFromSupervision()));
	
	m_timer->start();
}
void CWinSchedulerModel::saveSequences()
{
    QString sListSequenceNum ="0xffff096d|m_ListSequenceNum";
    QString sListSequenceDuree ="0xffff096e|m_ListSequenceDuree";
    
    for(int i=0; i< NBR_SEQUENCE_CYCLE_MAX; ++i)
    {
        sListSequenceNum += "|" 
            + QString::number(((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceNum.pGetAt(i))->nGetVal());
        sListSequenceDuree += "|"
            + QString::number(((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(i))->nGetVal());

    }

    this->bWritePrivateProfileStringS("CListStream","m_ListSequenceNum", sListSequenceNum, "Config.ini");
    this->bWritePrivateProfileStringS("CListStream","m_ListSequenceDuree", sListSequenceDuree, "Config.ini");
    
}
QString CWinSchedulerModel::getNbCycleAvantZero()const
{
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->m_PeriodicCycleZero.ucGetVal());
}
QString CWinSchedulerModel::getRemoteControl()const
{
	return QString::number(m_pSupervision->getAnalyseur()->m_CmdRemoteControl.ucGetVal());
}
QString CWinSchedulerModel::getLblConfigSeuil(int arg_numStream, int arg_numMeasure)const
{
    QString sRetour = "NaN";
    if(    m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)
        && m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure))
    {
	    //Type de sueils (0=bas/bas 1=bas/haut 2=haut/haut)
        switch(m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_SettingThreshold.ucGetVal())
        {
        case 0:
            sRetour = tr("Bas/Bas");
            break;
        case 1:
            sRetour = tr("Bas/Haut");
            break;
        case 2:
        default: 
            sRetour = tr("Haut/Haut");
            break;
        }
    }
	return sRetour;
}
QString CWinSchedulerModel::getLblConfigSeuil(int arg_index)const
{
    int numVoie = 0;
    int numMesure = 0;
    int index = 0;
    
    for(int i=0; i< getNbStream() ; ++i)
    {
        for(int j=0; j<getNbMeasure(); ++j)
        {
            if(arg_index == index)
            {
                numVoie = i;
                numMesure = j;
                break;
            }
			++index;
        }
        ++index;
    }
    QString sRetour = "NaN";
    if(    m_pSupervision->getAnalyseur()->pGetAt(numVoie)
        && m_pSupervision->getAnalyseur()->pGetAt(numVoie)->pGetAt(numMesure))
    {
	    //Type de sueils (0=bas/bas 1=bas/haut 2=haut/haut)
        switch(m_pSupervision->getAnalyseur()->pGetAt(numVoie)->pGetAt(numMesure)->m_SettingThreshold.ucGetVal())
        {
        case 0:
            sRetour = tr("Bas/Bas");
            break;
        case 1:
            sRetour = tr("Bas/Haut");
            break;
        case 2:
        default: 
            sRetour = tr("Haut/Haut");
            break;
        }
    }
	return sRetour;
}
int CWinSchedulerModel::getConfigSeuil(int arg_numStream, int arg_numMeasure)const
{
     if(    m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)
        && m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure))
    {
        return m_pSupervision->getAnalyseur()->pGetAt(arg_numStream)->pGetAt(arg_numMeasure)->m_SettingThreshold.ucGetVal();
    }
    return 2;
}
QString CWinSchedulerModel::getConsigneGain()const
{
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->m_OpticalSetPoint.nGetVal());
}
QString CWinSchedulerModel::getReglagePression()const
{
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->m_WaterFailureSetPoint.fGetVal(),'f', 2);
}
QString CWinSchedulerModel::getTempsVoieAttente()const
{
    //UNIQUEMENT POUR LE TH QUI EST PARTIE LE 12/2012 A VIRER QUAND LE SEQUENCEUR EST FAIT
    if(m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(1))
	    return QString::number(((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(1))->nGetVal());
    else
        return QString("255555");
}
QString CWinSchedulerModel::getNumEscalveJBUS()
{
    /*TCHAR szText[250];
    TCHAR szTextRetour[250];
    TCHAR szText2[250];
    QString sRetour;

   
    QTime t;
     t.start();
    _stprintf(szText,_T("InterfaceJbusSlave.ini"));
	
    sRetour = dwGetPrivateProfileString(_T("Config")
                            , _T("m_bNumInterface"),_T("0")
                            , szTextRetour
                            , sizeof(szTextRetour)/sizeof(TCHAR)
                            , szGetFullPathName(szText,szText2));
   
    qDebug() << "TEMPS " << t.elapsed();
    qDebug() << "RETOUR " << sRetour();
    
    t.restart();
    qDebug() << "TEMPS " << t.elapsed();
    qDebug() << "RETOUR " << sRetour();*/

    //this->sGetPrivateProfileString("Config","m_bNumInterface","0", "InterfaceJbusSlave.ini");
    return sGetPrivateProfileString("Config","m_bNumInterface","0", "InterfaceJbusSlave.ini");   
	    
    
    //QSettings iniFile("InterfaceJbusSlave.ini", QSettings::IniFormat);
    //iniFile.setIniCodec("UTF-16");
    ////iniFile.setPath(QSettings::IniFormat,QSettings::UserScope, "InterfaceJbusSlave.ini" );
    //iniFile.beginGroup("Config");
    //qDebug() << "Status " <<iniFile.status();
    //qDebug() << "Format " <<iniFile.format();
    //qDebug() << "isWritable " <<iniFile.isWritable();
    //qDebug() << "fileName " <<iniFile.fileName();
    //qDebug() << "IniCodec  " <<iniFile.iniCodec()->name();
    //iniFile.setValue("blim", "hokok");
    //iniFile.setValue("blam", "FABCO");
    //iniFile.sync();

    //QStringList keys = iniFile.allKeys();
    //qDebug() << "KEYS " <<keys;
    //return iniFile.value("m_bNumInterface", 99).toString();
    
}
int CWinSchedulerModel::getNbSequence()const
{ 
    int cpt =0;
    for(int i=0; i< NBR_SEQUENCE_CYCLE_MAX; ++i)
    {
        CElemInt16* elem =(CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(i);
        if(elem->nGetVal() > 0)
            ++cpt;
    }
    return cpt;
}
int CWinSchedulerModel::getNbStream()const
{
    return m_pSupervision->getAnalyseur()->iGetNbrStream();
}
int CWinSchedulerModel::getNbMeasure()const
{
    return m_pSupervision->getAnalyseur()->pGetAt(0)->iGetNbrMesure();
}
Sequence CWinSchedulerModel::getSequence(int arg_numSeq) const
{
    Sequence seq = {0,0};
   
    if(arg_numSeq < NBR_SEQUENCE_CYCLE_MAX)
    {
        seq.iDuree = ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(arg_numSeq))->nGetVal();
        seq.iStream = ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceNum.pGetAt(arg_numSeq))->nGetVal();
    }
    return seq;
}
void CWinSchedulerModel::setSequence(Sequence arg_seq, int arg_numSeq)
{
	qDebug() << "CWinSchedulerModel::setSequence(Sequence arg_seq, int arg_numSeq)" << arg_seq.iDuree;
    if(arg_numSeq < NBR_SEQUENCE_CYCLE_MAX)
    {
        ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(arg_numSeq))->bSetVal(arg_seq.iDuree);
        ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceNum.pGetAt(arg_numSeq))->bSetVal(arg_seq.iStream);
    }
	qDebug() << "CWinSchedulerModel::setSequence(Sequence arg_seq, int arg_numSeq)" <<         ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(arg_numSeq))->nGetVal();
}
void CWinSchedulerModel::setConfigSeuil(int arg_index, int arg_config)
{
    int numVoie = 0;
    int numMesure = 0;
    int index = 0;
    
    for(int i=0; i< this->getNbStream() ; ++i)
    {
        for(int j=0; j< this->getNbMeasure(); ++j)
        {
            if(arg_index == index)
            {
                numVoie = i;
                numMesure = j;
                break;
            }
			++index;
        }
        ++index;
    }
    if(    m_pSupervision->getAnalyseur()->pGetAt(numVoie)
        && m_pSupervision->getAnalyseur()->pGetAt(numVoie)->pGetAt(numMesure))
    {
        m_pSupervision->getAnalyseur()->pGetAt(numVoie)->pGetAt(numMesure)->m_SettingThreshold.bSetVal(arg_config);
        QString section = "CStream" + QString::number(numVoie) + "_CMesure" + QString::number(numMesure);
		qDebug() << section ;
        CMesureModel::writeElemConfigIni((wchar_t*)section.utf16()
							, _T("m_SettingThreshold")
							, &m_pSupervision->getAnalyseur()->pGetAt(numVoie)->pGetAt(numMesure)->m_SettingThreshold);
    }
}
void CWinSchedulerModel::deleteSequence(int arg_numSeq){
    
    while(  arg_numSeq+1 < NBR_SEQUENCE_CYCLE_MAX 
        && ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(arg_numSeq+1))->nGetVal() !=0 )
    {
        ((CElemInt16*)m_pSupervision->getAnalyseur()
            ->m_ListSequenceDuree.pGetAt(arg_numSeq))->bSetVal(((CElemInt16*)m_pSupervision->getAnalyseur()
            ->m_ListSequenceDuree.pGetAt(arg_numSeq+1))->nGetVal());
        ((CElemInt16*)m_pSupervision->getAnalyseur()
            ->m_ListSequenceNum.pGetAt(arg_numSeq))->bSetVal(((CElemInt16*)m_pSupervision->getAnalyseur()
            ->m_ListSequenceNum.pGetAt(arg_numSeq+1))->nGetVal());
        ++arg_numSeq;
    }
    ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(arg_numSeq))->bSetVal(0);
    ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceNum.pGetAt(arg_numSeq))->bSetVal(0);
    
}

QString CWinSchedulerModel::getConsigneTemperature()const
{
	return QString::number(m_pSupervision->getAnalyseur()->pGetAt(0)->m_CellTemperatureSetPoint.fGetVal(),'f', 2);
}


void CWinSchedulerModel::setNbCycleAvantZero(QString arg_nbCycle)
{
	m_pSupervision->getAnalyseur()->pGetAt(0)->m_iNbCycleZero = 1;
	m_pSupervision->getAnalyseur()->pGetAt(0)->m_PeriodicCycleZero.bSetVal((BYTE)arg_nbCycle.toShort(0, 10));
	CMesureModel::writeElemConfigIni(_T("CStream0")
							, _T("m_PeriodicCycleZero")
							, &m_pSupervision->getAnalyseur()->pGetAt(0)->m_PeriodicCycleZero);

}
void CWinSchedulerModel::setRemoteControl(QString arg_nbCycle)
{

	m_pSupervision->getAnalyseur()->m_CmdRemoteControl.bSetVal((BYTE)arg_nbCycle.toShort(0, 10));
	CMesureModel::writeElemConfigIni(_T("CListStream")
							, _T("m_CmdRemoteControl")
							, &m_pSupervision->getAnalyseur()->m_CmdRemoteControl);

}
void CWinSchedulerModel::setConsigneGain(QString arg)
{

	m_pSupervision->getAnalyseur()->pGetAt(0)->m_OpticalSetPoint.bSetVal(arg.toInt());
	CMesureModel::writeElemConfigIni(_T("CStream0")
							, _T("m_OpticalSetPoint")
							, &m_pSupervision->getAnalyseur()->pGetAt(0)->m_OpticalSetPoint);

}
void CWinSchedulerModel::setConsigneTemperature(QString arg_nbCycle)
{

	m_pSupervision->getAnalyseur()->pGetAt(0)->m_CellTemperatureSetPoint.bSetVal(arg_nbCycle.toFloat());
	CMesureModel::writeElemConfigIni(_T("CStream0")
							, _T("m_CellTemperatureSetPoint")
							, &m_pSupervision->getAnalyseur()->pGetAt(0)->m_CellTemperatureSetPoint);

}
void CWinSchedulerModel::setReglagePression(QString arg_nbCycle)
{

	m_pSupervision->getAnalyseur()->pGetAt(0)->m_WaterFailureSetPoint.bSetVal(arg_nbCycle.toFloat());
	CMesureModel::writeElemConfigIni(_T("CStream0")
							, _T("m_WaterFailureSetPoint")
							, &m_pSupervision->getAnalyseur()->pGetAt(0)->m_WaterFailureSetPoint);

}

void CWinSchedulerModel::setTempsVoieAttente(QString arg_nbCycle)
{
        qDebug() << " CWinSchedulerModel::setTempsVoieAttente(QString arg_nbCycle)";
  
	if(m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(1)) //Si sur la voie attente
	{
        qDebug() << " m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(1)";
	      ((CElemInt16*)m_pSupervision->getAnalyseur()->m_ListSequenceDuree.pGetAt(1))->bSetVal(arg_nbCycle.toInt());
    }
}

void CWinSchedulerModel::setNumEscalveJBUS(QString arg_numEscalve)
{
    /*QTime t;
    t.start();
    TCHAR szText[260];
	TCHAR szText2[260];
	
	
	_stprintf(szText,_T("InterfaceJbusSlave.ini"));
	szGetFullPathName(szText,szText2);
	bWritePrivateProfileString(_T("Config")
							, _T("m_bNumInterface")
							, (WCHAR *)arg_numEscalve.utf16()
							, szGetFullPathName(szText,szText2));
    qDebug() << "TIME " << t.elapsed();
    t.restart();*/
    this->bWritePrivateProfileStringS("Config","m_bNumInterface", arg_numEscalve, "InterfaceJbusSlave.ini");
   // qDebug() << "TIME " << t.elapsed();

}

QString CWinSchedulerModel::sGetPrivateProfileString(const QString arg_sSection, const QString arg_sKey, const QString arg_sDefault, const QString arg_sFileIni)
{
    int indexStart=-1;
    int indexEnd=-1;
    QString sReturn=arg_sDefault;
   
    QFile file(arg_sFileIni);
	
    file.open(QIODevice::ReadOnly);
	if(file.exists() && file.isOpen())
    {
		
        QByteArray byteArray = file.readAll();
        if(!byteArray.isEmpty())
        {
            QTextCodec* textCodec = QTextCodec::codecForName("UTF-16");
            QString sAllFileContent = textCodec->toUnicode(byteArray);
            QString sSection = "[" + arg_sSection + "]";
            //qDebug() << "SECTION " << sSection;
            indexStart = sAllFileContent.indexOf(sSection, 0, Qt::CaseInsensitive);
            //qDebug() << "INDEX " << indexStart;
            if (indexStart != -1)
            {
                indexStart += sSection.count();
              //  qDebug() << "INDEX " << indexStart;

                QString sKey = arg_sKey + "=";
                //qDebug() << "KEY " << sKey;

                indexStart = sAllFileContent.indexOf(sKey, indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX " << indexStart;
                
                indexStart += sKey.count();	
                //qDebug() << "INDEX " << indexStart;

                indexEnd = sAllFileContent.indexOf("\r", indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX FIN" << indexEnd;

                if(indexEnd == -1)
                    indexEnd = sAllFileContent.indexOf("\n", indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX FIN" << indexEnd;
                sReturn = sAllFileContent.mid(indexStart, indexEnd-indexStart);

//                qDebug() << sReturn ;
            }
        }
    }
    
    return sReturn;
}
QString CWinSchedulerModel::sGetPrivateProfileString2(const QString arg_sSection, const QString arg_sKey, const QString arg_sDefault, const QString arg_sFileIni)
{
    int indexStart=-1;
    int indexEnd=-1;
    QString sReturn=arg_sDefault;
   
    QFile file(arg_sFileIni);
	
    file.open(QIODevice::ReadOnly);
	if(file.exists() && file.isOpen())
    {
		
        QByteArray byteArray = file.readAll();
        if(!byteArray.isEmpty())
        {
            QTextCodec* textCodec = QTextCodec::codecForName("UTF-16");
            QString sAllFileContent = textCodec->toUnicode(byteArray);
            QString sSection = "[" + arg_sSection + "]";
            //qDebug() << "SECTION " << sSection;
            indexStart = sAllFileContent.indexOf(sSection, 0, Qt::CaseInsensitive);
            //qDebug() << "INDEX " << indexStart;
            if (indexStart != -1)
            {
                indexStart += sSection.count();
              //  qDebug() << "INDEX " << indexStart;

                QString sKey = arg_sKey + "=";
                //qDebug() << "KEY " << sKey;

                indexStart = sAllFileContent.indexOf(sKey, indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX " << indexStart;
                
                indexStart += sKey.count();	
                //qDebug() << "INDEX " << indexStart;

                indexEnd = sAllFileContent.indexOf("\r", indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX FIN" << indexEnd;

                if(indexEnd == -1)
                    indexEnd = sAllFileContent.indexOf("\n", indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX FIN" << indexEnd;
                sReturn = sAllFileContent.mid(indexStart, indexEnd-indexStart);

//                qDebug() << sReturn ;
            }
        }
    }
    
    return sReturn;
}
bool CWinSchedulerModel::bWritePrivateProfileStringS(const QString arg_sSection, const QString arg_sKey, const QString arg_sValue, const QString arg_sFileIni)
{
    int indexStart=-1;
    int indexEnd=-1;
    QString sOldValue;
    QFile file(arg_sFileIni);
	
    file.open(QIODevice::ReadWrite);
	if(file.exists() && file.isOpen())
    {
		
        QByteArray byteArray = file.readAll();
        if(!byteArray.isEmpty())
        {
            QTextCodec* textCodec = QTextCodec::codecForName("UTF-16");
            QString sAllFileContent = textCodec->toUnicode(byteArray);
            QString sSection = "[" + arg_sSection + "]";
            //qDebug() << "SECTION " << sSection;
            indexStart = sAllFileContent.indexOf(sSection, 0, Qt::CaseInsensitive);
            //qDebug() << "INDEX " << indexStart;
            if (indexStart != -1)
            {
                indexStart += sSection.count();
              //  qDebug() << "INDEX " << indexStart;

                QString sKey = arg_sKey + "=";
                //qDebug() << "KEY " << sKey;

                indexStart = sAllFileContent.indexOf(sKey, indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX " << indexStart;
                
                indexStart += sKey.count();	
                //qDebug() << "INDEX " << indexStart;

                indexEnd = sAllFileContent.indexOf("\r", indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX FIN" << indexEnd;

                if(indexEnd == -1)
                    indexEnd = sAllFileContent.indexOf("\n", indexStart, Qt::CaseInsensitive);
                //qDebug() << "INDEX FIN" << indexEnd;
                sOldValue = sAllFileContent.mid(indexStart, indexEnd-indexStart);
                sAllFileContent.replace(indexStart, sOldValue.count(), arg_sValue);
                //qDebug() << "STRINF " << sAllFileContent;
                byteArray = textCodec->fromUnicode(sAllFileContent);
                file.reset();
                file.write(byteArray);
                return true;

            }
        }
    }
   
    
    return false;
}

QString CWinSchedulerModel::getYear()
{
	return QString::number(QDate::currentDate().year());
}
QString CWinSchedulerModel::getMonth()
{
	return QString::number(QDate::currentDate().month());
}
QString CWinSchedulerModel::getDay()
{
	return QString::number(QDate::currentDate().day());
}
QString CWinSchedulerModel::getHour()
{
	return QString::number(QTime::currentTime().hour());
}
QString CWinSchedulerModel::getMinute()
{
	return QString::number(QTime::currentTime().minute());
}
void CWinSchedulerModel::setYear(const QString arg)
{
	
#ifdef _WINDOWS 
	SYSTEMTIME localTime;
	GetLocalTime(&localTime);
	localTime.wYear = arg.toInt();
	SetLocalTime(&localTime);
	/*	if (SetLocalTime(&localTime) != 0)
		{
			// ok
		}
		else
		{
			// failed
		}*/
#elif
	qdebug()<< "AUTRE SYSTEM QUE WINDOWS";erreur compile
#endif

}
void CWinSchedulerModel::setMonth(const QString arg)
{
#ifdef _WINDOWS 
	SYSTEMTIME localTime;
	GetLocalTime(&localTime);
	localTime.wMonth = arg.toInt();
	SetLocalTime(&localTime);
#elif
	cout << "AUTRE SYSTEM QUE WINDOWS";
#endif
}
void CWinSchedulerModel::setDay(const QString arg)
{
#ifdef _WINDOWS 
	SYSTEMTIME localTime;
	GetLocalTime(&localTime);
	localTime.wDay = arg.toInt();
	SetLocalTime(&localTime);
#elif
	cout << "AUTRE SYSTEM QUE WINDOWS";
#endif
}
void CWinSchedulerModel::setHour(const QString arg)
{
#ifdef _WINDOWS 
	SYSTEMTIME localTime;
	GetLocalTime(&localTime);
	localTime.wHour = arg.toInt();
	SetLocalTime(&localTime);
#elif
	cout << "AUTRE SYSTEM QUE WINDOWS";
#endif
}
void CWinSchedulerModel::setMinute(const QString arg)
{
#ifdef _WINDOWS 
	SYSTEMTIME localTime;
	GetLocalTime(&localTime);
	localTime.wMinute = arg.toInt();
	SetLocalTime(&localTime);
#elif
	cout << "AUTRE SYSTEM QUE WINDOWS";
#endif
}
void CWinSchedulerModel::setDateTime(const QString arg_Year, const QString arg_Month, const QString arg_Day, const QString arg_Hour, const QString arg_Minute)
{
#ifdef _WINDOWS 
	SYSTEMTIME localTime;
	GetLocalTime(&localTime);
	localTime.wYear = arg_Year.toInt();
	localTime.wMonth = arg_Month.toInt();
	localTime.wDay = arg_Day.toInt();
	localTime.wHour = arg_Hour.toInt();
	localTime.wMinute = arg_Minute.toInt();
	SetLocalTime(&localTime);
#elif
	cout << "AUTRE SYSTEM QUE WINDOWS";
#endif
}
