/****************************************************************************
** Meta object code from reading C++ file 'CDialogPassword.h'
**
** Created: Thu 19. Dec 09:22:08 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CDialogPassword.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CDialogPassword.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CDialogPassword[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
      11,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      17,   16,   16,   16, 0x0a,
      33,   16,   16,   16, 0x0a,
      48,   16,   16,   16, 0x0a,
      63,   16,   16,   16, 0x0a,
      80,   16,   16,   16, 0x0a,
      96,   16,   16,   16, 0x0a,
     112,   16,   16,   16, 0x0a,
     127,   16,   16,   16, 0x0a,
     144,   16,   16,   16, 0x0a,
     161,   16,   16,   16, 0x0a,
     177,   16,   16,   16, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CDialogPassword[] = {
    "CDialogPassword\0\0btZeroPressed()\0"
    "btOnePressed()\0btTwoPressed()\0"
    "btThreePressed()\0btFourPressed()\0"
    "btFivePressed()\0btSixPressed()\0"
    "btSevenPressed()\0btEightPressed()\0"
    "btNinePressed()\0btDeletePressed()\0"
};

void CDialogPassword::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CDialogPassword *_t = static_cast<CDialogPassword *>(_o);
        switch (_id) {
        case 0: _t->btZeroPressed(); break;
        case 1: _t->btOnePressed(); break;
        case 2: _t->btTwoPressed(); break;
        case 3: _t->btThreePressed(); break;
        case 4: _t->btFourPressed(); break;
        case 5: _t->btFivePressed(); break;
        case 6: _t->btSixPressed(); break;
        case 7: _t->btSevenPressed(); break;
        case 8: _t->btEightPressed(); break;
        case 9: _t->btNinePressed(); break;
        case 10: _t->btDeletePressed(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObjectExtraData CDialogPassword::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CDialogPassword::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_CDialogPassword,
      qt_meta_data_CDialogPassword, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CDialogPassword::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CDialogPassword::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CDialogPassword::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CDialogPassword))
        return static_cast<void*>(const_cast< CDialogPassword*>(this));
    return QDialog::qt_metacast(_clname);
}

int CDialogPassword::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 11)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 11;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
