/****************************************************************************
** Meta object code from reading C++ file 'CDialogStreamChoice.h'
**
** Created: Thu 19. Dec 09:22:07 2013
**      by: The Qt Meta Object Compiler version 63 (Qt 4.8.4)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../CDialogStreamChoice.h"
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'CDialogStreamChoice.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 63
#error "This file was generated using the moc from 4.8.4. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
static const uint qt_meta_data_CDialogStreamChoice[] = {

 // content:
       6,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       0,       // signalCount

 // slots: signature, parameters, type, tag, flags
      21,   20,   20,   20, 0x0a,
      36,   20,   20,   20, 0x0a,
      51,   20,   20,   20, 0x0a,
      68,   20,   20,   20, 0x0a,
      84,   20,   20,   20, 0x0a,
     100,   20,   20,   20, 0x0a,
     115,   20,   20,   20, 0x0a,

       0        // eod
};

static const char qt_meta_stringdata_CDialogStreamChoice[] = {
    "CDialogStreamChoice\0\0btOnePressed()\0"
    "btTwoPressed()\0btThreePressed()\0"
    "btFourPressed()\0btFivePressed()\0"
    "btSixPressed()\0btPausePressed()\0"
};

void CDialogStreamChoice::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Q_ASSERT(staticMetaObject.cast(_o));
        CDialogStreamChoice *_t = static_cast<CDialogStreamChoice *>(_o);
        switch (_id) {
        case 0: _t->btOnePressed(); break;
        case 1: _t->btTwoPressed(); break;
        case 2: _t->btThreePressed(); break;
        case 3: _t->btFourPressed(); break;
        case 4: _t->btFivePressed(); break;
        case 5: _t->btSixPressed(); break;
        case 6: _t->btPausePressed(); break;
        default: ;
        }
    }
    Q_UNUSED(_a);
}

const QMetaObjectExtraData CDialogStreamChoice::staticMetaObjectExtraData = {
    0,  qt_static_metacall 
};

const QMetaObject CDialogStreamChoice::staticMetaObject = {
    { &QDialog::staticMetaObject, qt_meta_stringdata_CDialogStreamChoice,
      qt_meta_data_CDialogStreamChoice, &staticMetaObjectExtraData }
};

#ifdef Q_NO_DATA_RELOCATION
const QMetaObject &CDialogStreamChoice::getStaticMetaObject() { return staticMetaObject; }
#endif //Q_NO_DATA_RELOCATION

const QMetaObject *CDialogStreamChoice::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->metaObject : &staticMetaObject;
}

void *CDialogStreamChoice::qt_metacast(const char *_clname)
{
    if (!_clname) return 0;
    if (!strcmp(_clname, qt_meta_stringdata_CDialogStreamChoice))
        return static_cast<void*>(const_cast< CDialogStreamChoice*>(this));
    return QDialog::qt_metacast(_clname);
}

int CDialogStreamChoice::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QDialog::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    }
    return _id;
}
QT_END_MOC_NAMESPACE
