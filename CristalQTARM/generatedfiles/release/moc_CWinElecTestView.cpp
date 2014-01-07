/****************************************************************************
** Meta object code from reading C++ file 'CWinElecTestView.h'
**
** Created: Thu 19. Dec 09:22:07 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinElecTestView.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinElecTestView.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinElecTestView[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       4,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      30,   18,   17,   17, 0x0a,
      56,   18,   17,   17, 0x0a,
      76,   18,   17,   17, 0x0a,
      99,   17,   17,   17, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinElecTestView[] = {
    "CWinElecTestView\0\0argnNumPage\0"
    "loadPageExternalCard(int)\0loadPageEntree(int)\0"
    "loadPageSortieAna(int)\0slotTemperatureUpdated()\0"
};

void CWinElecTestView::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinElecTestView *_t = static_cast<CWinElecTestView *>(_o);
        switch (_id) {
        case 0: _t->loadPageExternalCard((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 1: _t->loadPageEntree((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 2: _t->loadPageSortieAna((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->slotTemperatureUpdated(); break;
        default: ;
        }
    }
}

const QMetaObjectExtraData CWinElecTestView::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinElecTestView::staticMetaObject = {
    { &QWidget::staticMetaObject, qt_meta_stringdata_CWinElecTestView,
      qt_meta_data_CWinElecTestView, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinElecTestView::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinElecTestView::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinElecTestView::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinElecTestView))
        return static_cast<void*>(const_cast< CWinElecTestView*>(this));
    return QWidget::qt_metacast(_clname);
}

int CWinElecTestView::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QWidget::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 4)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 4;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
