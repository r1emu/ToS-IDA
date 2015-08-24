#!/usr/bin/python
"""
Tree of Savior IDAPython Script
Automic rename of Lua related functions
"""

import idaapi
import idc

if GetStrucIdByName ("lua_State") == BADADDR:
    print "ERROR : Add definition of lua_State first.";
    print '''
typedef union {
  void *gc;
  void *p;
  int n;
  int b;
} LuaValue;

struct lua_TValue
{
  LuaValue value;
  int tt;
};

typedef struct lua_TValue LuaTValue;

typedef LuaTValue *StkId;

struct lua_State
{
  void *next;
  unsigned __int8 tt;
  unsigned __int8 marked;
  unsigned __int8 status;
  StkId top;
  StkId base;
  void *l_G;
  void *ci;
  void *savedpc;
  StkId stack_last;
  StkId stack;
  void *end_ci;
  void *base_ci;
  int stacksize;
  int size_ci;
  unsigned __int16 nCcalls;
  unsigned __int16 baseCcalls;
  unsigned __int8 hookmask;
  unsigned __int8 allowhook;
  int basehookcount;
  int hookcount;
  void *hook;
  LuaTValue l_gt;
  LuaTValue env;
  void *openupval;
  void *gclist;
  void *errorJmp;
};
'''.strip();

else:
    # Tip : GetSessionObject is already defined with ToSrenameDebugFunctions.py for being discovered
    # Just look for XRef of GetSessionObject and you'll find LuaExtern__declGlobalFunction
    LuaExtern__declGlobalFunction = 0x0D18570; # ICBT3

    def MakeNameForce (address, name):
        x = 2;
        newName = name;
        while (MakeNameEx (address, newName, SN_NOWARN) == 0):
            newName = "%s_%d" % (name, x);
            x = x + 1;
        return newName;

    # Rename all functions declared with LuaExtern__declGlobalFunction
    occ = RfirstB (LuaExtern__declGlobalFunction);
    while occ != BADADDR:
        routineAddress = Dword (occ - 5 - 4);
        routineName = GetString (Dword (occ - 4));
        occ = RnextB (LuaExtern__declGlobalFunction, occ);
        name = MakeNameForce (routineAddress, routineName);
        SetType (routineAddress, "int __cdecl %s (lua_State * luaState)" % name);