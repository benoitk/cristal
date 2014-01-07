/****************************************************************************
** Meta object code from reading C++ file 'CWinExternalCardModel.h'
**
** Created: Thu 19. Dec 09:22:06 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CWinExternalCardModel.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CWinExternalCardModel.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CWinExternalCardModel[] = {

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
      23,   22,   22,   22, 0x0a,
      40,   22,   22,   22, 0x0a,
      62,   22,   22,   22, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CWinExternalCardModel[] = {
    "CWinExternalCardModel\0\0trigerWatchdog()\0"
    "slotTrigerDigitOut8()\0cmdGetEntrees()\0"
};

void CWinExternalCardModel::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CWinExternalCardModel *_t = static_cast<CWinExternalCardModel *>(_o);
        switch (_id) {
        case 0: _t->trigerWatchdog(); break;
        case 1: _t->slotTrigerDigitOut8(); break;
        case 2: _t->cmdGetEntrees(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObjectExtraData CWinExternalCardModel::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CWinExternalCardModel::staticMetaObject = {
    { &QObject::staticMetaObject, qt_meta_stringdata_CWinExternalCardModel,
      qt_meta_data_CWinExternalCardModel, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CWinExternalCardModel::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CWinExternalCardModel::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CWinExternalCardModel::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CWinExternalCardModel))
        return static_cast<void*>(const_cast< CWinExternalCardModel*>(this));
    if (!strcmp(_clname, "CCardJBusModel"))
        return static_cast< CCardJBusModel*>(const_cast< CWinExternalCardModel*>(this));
    return QObject::qt_metacast(_clname);
}

int CWinExternalCardModel::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QObject::qt_metacall(_c, _id, _a);
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
