/****************************************************************************
** Meta object code from reading C++ file 'CDialogResultatEtalon.h'
**
** Created: Thu 19. Dec 09:22:07 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CDialogResultatEtalon.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CDialogResultatEtalon.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CDialogResultatEtalon[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      23,   22,   22,   22, 0x0a,
      40,   22,   22,   22, 0x0a,
      58,   22,   22,   22, 0x0a,
      76,   22,   22,   22, 0x0a,
      91,   22,   22,   22, 0x0a,
     107,   22,   22,   22, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CDialogResultatEtalon[] = {
    "CDialogResultatEtalon\0\0btValuePressed()\0"
    "btValue2Pressed()\0btValue3Pressed()\0"
    "valueChanged()\0value2Changed()\0"
    "value3Changed()\0"
};

void CDialogResultatEtalon::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CDialogResultatEtalon *_t = static_cast<CDialogResultatEtalon *>(_o);
        switch (_id) {
        case 0: _t->btValuePressed(); break;
        case 1: _t->btValue2Pressed(); break;
        case 2: _t->btValue3Pressed(); break;
        case 3: _t->valueChanged(); break;
        case 4: _t->value2Changed(); break;
        case 5: _t->value3Changed(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObjectExtraData CDialogResultatEtalon::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CDialogResultatEtalon::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_CDialogResultatEtalon,
      qt_meta_data_CDialogResultatEtalon, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CDialogResultatEtalon::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CDialogResultatEtalon::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CDialogResultatEtalon::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CDialogResultatEtalon))
        return static_cast<void*>(const_cast< CDialogResultatEtalon*>(this));
    return QDialog::qt_metacast(_clname);
}

int CDialogResultatEtalon::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
