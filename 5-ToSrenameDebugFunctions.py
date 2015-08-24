#!/usr/bin/python
"""
Tree of Savior IDAPython Script
Automatic rename of functions containing a debug message
"""
import re
import idautils
import idc
import idaapi

s = idautils.Strings(False)
s.setup(strtypes=Strings.STR_UNICODE | Strings.STR_C)
for i, v in enumerate(s):
    if v is None:
        print("Failed to retrieve string index %d" % i)
    else:
        matchObj = re.match( r'.*(?:\_\_.*?) (.*)\(.*\)', str(v), re.M|re.I) # Regex to get strings that contain a function name
        if matchObj and "<" not in matchObj.group(1) and ">" not in matchObj.group(1):
           sub1 = re.sub(r'<[^)]*>', '', matchObj.group(1))
           sub2 = re.sub(r'\[[^)]*\]', '', sub1)
           print "Found function: " + sub2.strip()
           for xref in XrefsTo(v.ea, 0): # Get xrefs of the strings we find
               func = idaapi.get_func(xref.frm) # Get the function the xref is in
               if func is not None:
                   print "Renaming " + idaapi.get_func_name(func.startEA) + " to " + sub2.strip() + " at " + hex(func.startEA),
                   if MakeNameEx(func.startEA, sub2.strip(), SN_NOWARN):
                       print " Success"
                   else:
                       print " Fail"
           print ""
