#!/usr/bin/python
"""
Tree of Savior IDAPython Script
Automatic rename of DTB related functions
"""

import idaapi
import sys

# Check if DtbTable and DtbItem are present
if GetStrucIdByName ("DtbItem") == BADADDR or GetStrucIdByName ("DtbTable") == BADADDR:
    print "ERROR : Add definition of DtbItem and DtbTable first.";
    print '''
#pragma pack(push, 1)
struct DtbItem
{
  DtbItem *next;
  DtbItem **prev;
  DWORD schrageId;
  void *data;
  int field_10;
  int field_14;
  int sid;
};

struct DtbTable
{
  int size;
  DtbItem *dtbEmpty;
  int field_8;
  int field_C;
  DtbItem **table;
  void *dwordArray[3];
  int mask;
  int tableSizeMax;
  float float_1_0;
};
#pragma pack(pop)
'''.strip();

else:
    getObjectSignatureWord  = "55 "                  # push ebp
    getObjectSignatureWord += "8B EC "               # mov ebp, esp
    getObjectSignatureWord += "51 "                  # push ecx
    getObjectSignatureWord += "53 "                  # push ebx
    getObjectSignatureWord += "8B 5D 0C "            # mov ebx, [dword ss:arg2]
    getObjectSignatureWord += "0F B7 03 "            # movzx eax, [word ds:ebx]
    getObjectSignatureWord += "56 "                  # push esi
    getObjectSignatureWord += "57 "                  # push edi
    getObjectSignatureWord += "68 1D F3 01 00 "      # push 1F31D
    getObjectSignatureWord += "50 "                  # push eax
    getObjectSignatureWord += "8B F1 "               # mov esi, ecx
    getObjectSignatureWord += "FF 15 ? ? ? ? "       # call [dword ds:<&MSVCR100.ldiv>]
    getObjectSignatureWord += "69 D2 A7 41 00 00 "   # imul edx, edx, 41A7
    getObjectSignatureWord += "69 C0 14 0B 00 00 "   # imul eax, eax, 0B14

    getObjectSignatureDword  = "55 "                 # push ebp
    getObjectSignatureDword += "8B EC "              # mov ebp, esp
    getObjectSignatureDword += "51 "                 # push ecx
    getObjectSignatureDword += "53 "                 # push ebx
    getObjectSignatureDword += "8B 5D 0C "           # mov ebx, [dword ss:arg2]
    getObjectSignatureDword += "8B 03 "              # mov eax, [dword ds:ebx]
    getObjectSignatureDword += "56 "                 # push esi
    getObjectSignatureDword += "57 "                 # push edi
    getObjectSignatureDword += "68 1D F3 01 00 "     # push 1F31D
    getObjectSignatureDword += "50 "                 # push eax
    getObjectSignatureDword += "8B F1 "              # mov esi, ecx
    getObjectSignatureDword += "FF 15 ? ? ? ? "      # call [dword ds:<&MSVCR100.ldiv>]
    getObjectSignatureDword += "69 D2 A7 41 00 00 "  # imul edx, edx, 41A7
    getObjectSignatureDword += "69 C0 14 0B 00 00 "  # imul eax, eax, 0B14

    print "Finding all 'DTB WORD functions'"
    ea = 0;
    curId = 1;
    while 1:
        ea = FindBinary (ea, SEARCH_DOWN, getObjectSignatureWord);
        if (ea == BADADDR):
            print "Finished.";
            break;
        else:
            name = "DtbTable__getObject_WORD_%d" % curId;
            print "Found %s : %x" % (name, ea);
            MakeName (ea, name);
            SetType (ea, "void __thiscall %s (DtbTable *this, DtbItem **out, WORD *seed)" % name);
            ea = ea + 1;
            curId = curId + 1;

    print "Finding all 'DTB DWORD functions'"
    ea = 0;
    while 1:
        ea = FindBinary (ea, SEARCH_DOWN, getObjectSignatureDword);
        if (ea == BADADDR):
            print "Finished.";
            break;
        else:
            name = "DtbTable__getObject_DWORD_%d" % curId;
            print "Found %s : %x" % (name, ea);
            MakeName (ea, name);
            SetType (ea, "void __thiscall %s (DtbTable *this, DtbItem **out, WORD *seed)" % name);
            ea = ea + 1;
            curId = curId + 1;
