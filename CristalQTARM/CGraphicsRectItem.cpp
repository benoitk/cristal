#include "CGraphicsRectItem.h"

#include "header_qt.h"

#define SCENE_WIDTH 440
#define SCENE_HEIGHT 180
CGraphicsRectItem::CGraphicsRectItem( qreal x, qreal y, qreal width, qreal height
									, QGraphicsProxyWidget *arg_proxyLblInfo)
		:QGraphicsRectItem ( x, y, width, height),m_proxyLblInfo(arg_proxyLblInfo)
{
	
}

void CGraphicsRectItem::mousePressEvent(QGraphicsSceneMouseEvent * event)
{
	this->setRect(this->rect().x()-5, this->rect().y()-20, this->rect().width()+10, this->rect().height()+20);

	((QLabel*)m_proxyLblInfo->widget())->setText(m_sMesure + "\n"+m_sDate+"\n"+m_sHeure);
	m_proxyLblInfo->setVisible(true);
	
	//if(this->rect().x() < (SCENE_WIDTH/2))//afficher à droite
	//{
	//	m_proxyLblInfo->setPos(this->rect().x()+20, this->rect().y());
	//}
	//if(this->rect().x() > (SCENE_WIDTH/2))//afficher à gauche
	//{
	//	m_proxyLblInfo->setPos(this->rect().x()-m_sDate.count()*10, this->rect().y());
	//}	
}

void CGraphicsRectItem::mouseReleaseEvent ( QGraphicsSceneMouseEvent * event )
{
	((QLabel*)m_proxyLblInfo->widget())->setText("");
	m_proxyLblInfo->setVisible(false);
	
	this->setRect(this->rect().x()+5, this->rect().y()+20, this->rect().width()-10, this->rect().height()-20);
}
