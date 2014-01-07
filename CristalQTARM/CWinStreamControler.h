#ifndef CWIN_STREAM_CONTROLER
#define CWIN_STREAM_CONTROLER

#if defined(MULTI_STREAM)
    #define VOIE 0 
    #define MEASURE_1 1 
    #define MEASURE_2 2 
    #define MEASURE_3 3 
    #define MEASURE_4 4 
#else
    #define VOIE 99 
    #define MEASURE_1 0 
    #define MEASURE_2 1 
    #define MEASURE_3 2 
    #define MEASURE_4 3 
#endif

#include <QObject>

class CWinStreamModel;
class CWinStreamView;
class CSupervision;
class CWinMainControler;

class CWinStreamControler : public QObject
{

	Q_OBJECT

public:
	
	void execControler(int numStream);

public slots:

	void btBackPressed();
	void btOnVoieActivePressed();
	void btOffVoieActivePressed();
	void btNextPagePressed(int arg_numMesure);
	void btPreviousPagePressed(int arg_numMesure);
	void btEditPressed(int arg_index);
    void slotTabChanged(int arg_numTab);
	/*void btEdit1Pressed();
	void btEdit2Pressed();
	void btEdit3Pressed();
	void btEdit4Pressed();*/

private:
	CWinMainControler* m_pControler;
	CWinStreamModel* m_pModel;
	CWinStreamView* m_pView;
	CSupervision* m_pSupervision;
	static CWinStreamControler* singletonControler;

	QList<int> m_listNumPage;
	int m_nombrePages;
    int m_numCurrentStream;
    int m_numCurrentMeasure;

private:
	CWinStreamControler(CWinMainControler* argWinMainControler);

public:
	static	CWinStreamControler* getInstance(CWinMainControler* argWinMainControler);

};

#endif
