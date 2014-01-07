#ifndef CMeasure_CARD_MODEL
#define CMeasure_CARD_MODEL

#include <QObject>

class CCarteMesure;
class CAnalyseur;
class QTimer;

class CMeasureCardModel: public QObject
{
	Q_OBJECT
public:
	CMeasureCardModel(CCarteMesure *argpCarteMesure, CAnalyseur* argpAnalyseur);
	

private slots:
	void getDataFromMeasureCard();

private:
	void setConnexion();
	
	QTimer *m_timer;

};
#endif