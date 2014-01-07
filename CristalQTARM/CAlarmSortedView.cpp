#include "CAlarmSortedView.h"
#include "CAlarmSortFilterProxyModel.h"
#include "CDialogAlarm.h"
#include "header_qt.h"

#ifdef RES_640_480
    #define ROW_PER_PAGE 28
#else
    #define ROW_PER_PAGE 10 
#endif

CAlarmSortedView::CAlarmSortedView(CDialogAlarm *parent)
    : QWidget ( (QWidget*)parent ), m_filter(new CAlarmSortFilterProxyModel(ROW_PER_PAGE)), m_nbPage(1), m_numPage(0), m_parent(parent)
{

    m_layout = new QHBoxLayout();

    m_listView = new QListView(this);
    m_layout->addWidget(m_listView);

    /*m_btNext = new QPushButton(this);
    m_btNext->setObjectName("btNextPage");
    connect(m_btNext, SIGNAL(clicked()),m_filter ,SLOT(slotNextPage()));   
    m_layout->addWidget(m_btNext, 1, 0, Qt::AlignRight);
    
    m_btPrev = new QPushButton(this);
    m_btPrev->setObjectName("btPreviousPage");
    connect(m_btPrev, SIGNAL(clicked()),m_filter ,SLOT(slotPrevPage()));   
    m_layout->addWidget(m_btPrev, 1, 1, Qt::AlignLeft);*/

   /* m_btPrev->setEnabled(false);
    if(m_filter->getNbPage() < 2)
    {
        m_btNext->setEnabled(false);
    }*/
        
    m_listView->setEditTriggers( QAbstractItemView::NoEditTriggers );
    m_listView->setResizeMode(QListView::Adjust);
   
    m_layout->setContentsMargins ( 0, 0, 0, 0 );
    this->setLayout(m_layout);
    QSizePolicy expandPolicy(QSizePolicy::Expanding,QSizePolicy::Expanding);
    this->setSizePolicy(expandPolicy);
    connect(m_filter, SIGNAL(pageChanged()), this, SLOT(slotChangePage()));
    
    
    
}
void CAlarmSortedView::slotChangePage()
{
    //qDebug() << "m_filter->getNumPage()" << m_filter->getNumPage();
    //qDebug() << "m_filter->getNbPage()" << m_filter->getNbPage();
    if(m_filter->getNumPage() < (m_filter->getNbPage()-1) )
         m_parent->setEnabledBtNext(true);
    else
        m_parent->setEnabledBtNext(false);

    if(m_filter->getNumPage() > 0)
        m_parent->setEnabledBtPrev(true);
    else
        m_parent->setEnabledBtPrev(false);

}
CAlarmSortedView::~CAlarmSortedView()
{
    delete m_filter;
}

void CAlarmSortedView::setModel( QAbstractItemModel *model )
{
    m_filter->setSourceModel( model );
    m_listView->setModel( m_filter );
    
   
}

void CAlarmSortedView::slotNextPage()
{
    m_filter->slotNextPage();
}

void CAlarmSortedView::slotPrevPage()
{
    m_filter->slotPrevPage();
}