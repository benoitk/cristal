/****************************************************************************
** Meta object code from reading C++ file 'CAlarmSortedView.h'
**
** Created: Thu 19. Dec 09:22:08 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CAlarmSortedView.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CAlarmSortedView.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CAlarmSortedView[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       3,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      18,   17,   17,   17, 0x0a,
      35,   17,   17,   17, 0x0a,
      50,   17,   17,   17, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CAlarmSortedView[] = {
    "CAlarmSortedView\0\0slotChangePage()\0"
    "slotNextPage()\0slotPrevPage()\0"
};

void CAlarmSortedView::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CAlarmSortedView *_t = static_cast<CAlarmSortedView *>(_o);
        switch (_id) {
        case 0: _t->slotChangePage(); break;
        case 1: _t->slotNextPage(); break;
        case 2: _t->slotPrevPage(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObjectExtraData CAlarmSortedView::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CAlarmSortedView::staticMetaObject = {
    { &QWidget::staticMetaObject, qt_meta_stringdata_CAlarmSortedView,
      qt_meta_data_CAlarmSortedView, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CAlarmSortedView::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CAlarmSortedView::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CAlarmSortedView::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CAlarmSortedView))
        return static_cast<void*>(const_cast< CAlarmSortedView*>(this));
    return QWidget::qt_metacast(_clname);
}

int CAlarmSortedView::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 3)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 3;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
