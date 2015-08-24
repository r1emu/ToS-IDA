#!/usr/bin/python
"""
Tree of Savior IDAPython Script
Find LuaInterface getters
"""

import idaapi
import idautils
import idc


"""
Getter example : 
.text:00FEE870                     push    offset aFast    ; "FAST"
.text:00FEE875                     call    LuaInterface__getInstance
.text:00FEE87A                     mov     ecx, eax
.text:00FEE87C                     call    LuaInterface__getObject
.text:00FEE881                     mov     dword_14A17C8, eax
.text:00FEE886                     retn
"""

LuaInterface__getInstance = 0x00D75EF0
LuaInterface__getObject   = 0x00D75EA0
LuaInterface__getObjectEx = 0x00DBBCB0

MakeNameEx (LuaInterface__getInstance, "LuaInterface::getInstance", SN_NOWARN);
MakeNameEx (LuaInterface__getObject, "LuaInterface::getObject", SN_NOWARN);
MakeNameEx (LuaInterface__getObjectEx, "LuaInterface::getObjectEx", SN_NOWARN);

def MakeNameForce (address, name):
    x = 2;
    newName = name;
    while (MakeNameEx (address, newName, SN_NOWARN) == 0):
        newName = "%s_%d" % (name, x);
        x = x + 1;
        if x > 300:
            break;
    return newName;

occ = RfirstB (LuaInterface__getInstance);
while occ != BADADDR:
    pushAddress = PrevHead (occ);
    movAddress = NextHead (occ);
    getObjectAddress = NextHead (movAddress);
    movAddress2 = NextHead (getObjectAddress);
    retnAddress = NextHead (movAddress2);
    if (GetMnem (pushAddress) == "push" 
    and GetMnem (movAddress) == "mov" 
    and GetMnem (getObjectAddress) == "call" 
    and GetMnem (movAddress2) == "mov" 
    and GetMnem (retnAddress) == "retn"
    and GetOperandValue (getObjectAddress, 0) == LuaInterface__getObject):
        sidAddress = GetOperandValue (movAddress2, 0);
        strAddress = GetOperandValue (pushAddress, 0);
        MakeData (sidAddress, FF_DWRD, 4, 0);
        MakeNameForce (sidAddress, "SID_" + GetString (strAddress));

    occ = RnextB (LuaInterface__getInstance, occ);


"""
.text:00FFA080                     push    6
.text:00FFA082                     push    offset aCancel_0 ; "CANCEL"
.text:00FFA087                     call    sub_DBBCB0
.text:00FFA08C                     add     esp, 8
.text:00FFA08F                     mov     dword_2CE294C, eax
.text:00FFA094                     retn
"""
occ = RfirstB (LuaInterface__getObjectEx);
while occ != BADADDR:
    pushStrAddress = PrevHead (occ);
    pushSizeAddress = PrevHead (pushStrAddress);
    addAddress = NextHead (occ);
    movAddress = NextHead (addAddress);
    if (GetMnem (pushStrAddress) == "push" 
    and GetMnem (pushSizeAddress) == "push" 
    and GetMnem (addAddress) == "add" 
    and GetMnem (movAddress) == "mov"):
        sidAddress = GetOperandValue (movAddress, 0);
        strAddress = GetOperandValue (pushStrAddress, 0);
        if (strAddress != None):
            strValue = GetString (strAddress);
            if strValue != None:
                MakeNameForce (sidAddress, "SID_" + strValue);
    
    occ = RnextB (LuaInterface__getObjectEx, occ);