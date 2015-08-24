#!/usr/bin/python
"""
Tree of Savior IDAPython Script
Find packet listing
"""

import idaapi
import idautils
import idc
import os

gePacketTable__PACKET_TABLE__AddPacketSize = 0x09A8D70; # ICBT3

f = open ('PacketType.h', 'w');
fpy = open ('PacketType.py', 'w');
f.write ("typedef enum PacketType {\n\n");
packetsId = [];
packetsName = [];
packetsSize = [];

# Rename all functions declared with gePacketTable__PACKET_TABLE__AddPacketSize
occ = RfirstB (gePacketTable__PACKET_TABLE__AddPacketSize);
while occ != BADADDR:
    packetIdInsn = PrevHead (occ);
    packetSizeInsn = PrevHead (packetIdInsn);

    packetId = GetOperandValue (packetIdInsn, 0);
    packetSize = GetOperandValue (packetSizeInsn, 0);
    packetName = GetString (Dword (occ + 6));

    packetsId.append (packetId);
    packetsSize.append (packetSize);
    packetsName.append (packetName);
    
    packetLine = "\t%s = %d, // Size = %d" % (packetName, packetId, packetSize);
    f.write (packetLine + "\n");
    fpy.write ("packetsType[%d] = \"%s\" # Size = %d\n" % (packetId, packetName, packetSize));
    occ = RnextB (gePacketTable__PACKET_TABLE__AddPacketSize, occ);

f.write ('\n\tPACKET_TYPE_COUNT\n\n');
f.write ('}\tPacketType;\n\n');

# Write string association
f.write ("const PacketTypeInfo packetTypeInfo = {\n");
f.write ("    #define REGISTER_PACKET_TYPE_ENTRY(packetType, packetValue, packetSize) \\\n");
f.write ("        .packets[packetType] = {.value = packetValue, .size = packetSize, .string = STRINGIFY (packetType)}\n");
for name,id,size in zip (packetsName, packetsId, packetsSize):
    f.write ("    REGISTER_PACKET_TYPE_ENTRY (%s, %d, %d),\n" % (name, id, size));

f.write ("    #undef REGISTER_PACKET_TYPE_ENTRY\n};");

f.close ();
fpy.close ();

print "The structure has been written to : ";
print "%s" % (os.getcwd() + "\\PacketType.h");
print "%s" % (os.getcwd() + "\\PacketType.py");