#ifndef CLASS_GRAPHICS_RECT_ITEM
#define CLASS_GRAPHICS_RECT_ITEM

#include <QGraphicsRectItem>
#include <QString>
class QGraphicsSceneMouseEvent;
class QGraphicsProxyWidget;


//Redéffinission pour gérer les events
class CGraphicsRectItem: public QGraphicsRectItem
{

public:
	CGraphicsRectItem(qreal x, qreal y, qreal width, qreal height, QGraphicsProxyWidget *arg_proxyLblInfo);
	
    void mousePressEvent( QGraphicsSceneMouseEvent * event );
	void mouseReleaseEvent ( QGraphicsSceneMouseEvent * event );
	void setDate(const QString& arg_sDate){m_sDate=arg_sDate;};
	void setHeure(const QString& arg_sHeure){m_sHeure=arg_sHeure;};
	void setMesure(const QString& arg_sMesure){m_sMesure=arg_sMesure;};
	QString getDate(){return m_sDate;};
	QString getMesure(){return m_sMesure;};
	QString getHeure(){return m_sHeure;};
private:
	QGraphicsProxyWidget *m_proxyLblInfo;
	QString m_sDate;
	QString m_sHeure;
	QString m_sMesure;

};
#endif