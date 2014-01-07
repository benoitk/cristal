/****************************************************************************
** Meta object code from reading C++ file 'CDialogStopCycle.h'
**
** Created: Thu 19. Dec 09:22:07 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CDialogStopCycle.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CDialogStopCycle.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CDialogStopCycle[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       1,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      18,   17,   17,   17, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CDialogStopCycle[] = {
    "CDialogStopCycle\0\0stopCycle()\0"
};

void CDialogStopCycle::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CDialogStopCycle *_t = static_cast<CDialogStopCycle *>(_o);
        switch (_id) {
        case 0: _t->stopCycle(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObjectExtraData CDialogStopCycle::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CDialogStopCycle::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_CDialogStopCycle,
      qt_meta_data_CDialogStopCycle, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CDialogStopCycle::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CDialogStopCycle::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CDialogStopCycle::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CDialogStopCycle))
        return static_cast<void*>(const_cast< CDialogStopCycle*>(this));
    return QDialog::qt_metacast(_clname);
}

int CDialogStopCycle::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 1)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 1;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
