#ifndef ALARM_SORTED_VIEW
#define ALARM_SORTED_VIEW

#include <QWidget>

class QLabel;
class QLineEdit;
class QListView;
class QHBoxLayout;
class QAbstractItemModel;
class CAlarmSortFilterProxyModel;
class QPushButton;
class CDialogAlarm;

class CAlarmSortedView : public QWidget
{
    Q_OBJECT

public:
    explicit CAlarmSortedView( CDialogAlarm *parent = 0 );
    ~CAlarmSortedView();

    void setModel( QAbstractItemModel* model );
public slots:
    void slotChangePage();
    void slotNextPage();
    void slotPrevPage();

private:
    CDialogAlarm* m_parent;
    CAlarmSortFilterProxyModel *m_filter;
    QHBoxLayout *m_layout;
    QListView  *m_listView;
    /*QPushButton * m_btNext;
    QPushButton * m_btPrev;*/

    int m_nbPage;
    int m_numPage;

};


#endif