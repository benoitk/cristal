#ifndef ALARM_SORT_FILTER_PROXY_MODEL
#define ALARM_SORT_FILTER_PROXY_MODEL

#include <QSortFilterProxyModel>

class CAlarmSortFilterProxyModel : public QSortFilterProxyModel
{
    Q_OBJECT

public:
    explicit CAlarmSortFilterProxyModel(const int& arg_rowPerPage);
    
    bool filterAcceptsRow(int source_row,const QModelIndex & source_parent ) const;

    int getNbPage();
    int getNumPage(){return m_numPage;};
    void setRowPerPage(const int& arg_rowPerPage){m_rowPerPage = arg_rowPerPage;};

public slots:
    void slotNextPage();
    void slotPrevPage();

signals:
    void pageChanged();

private:
    int m_rowPerPage;
    int m_nbPage;
    int m_numPage;

};

#endif