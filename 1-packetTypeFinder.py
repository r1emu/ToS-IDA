#!/usr/bin/python
"""
Tree of Savior IDAPython Script
Find packet listing
"""

import idaapi
import idautils
import idc
import os

gePacketTable__PACKET_TABLE__AddPacketSize = 0x9E10E0; # ICBT2 ; Search "%d PacketCommandError MaxiMum -> %d"

fpy = open ('PacketType.py', 'w');
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
    # f.write (packetLine + "\n");
    fpy.write ("packetsType[%d] = \"%s\" # Size = %d\n" % (packetId, packetName, packetSize));
    occ = RnextB (gePacketTable__PACKET_TABLE__AddPacketSize, occ);

# Write .h
f = open ('PacketType.h', 'w');
f.write ("#define FOREACH_PACKET_TYPE(GENERATOR) \\\n");
for name,id,size in zip (packetsName, packetsId, packetsSize):
    f.write ("    GENERATOR(%s, %d, %d) \\\n" % (name, id, size));

"""
f.write ("const PacketTypeInfo packetTypeInfo = {\n");
f.write ("    #define REGISTER_PACKET_TYPE_ENTRY(packetType, packetValue, packetSize) \\\n");
f.write ("        .packets[packetType] = {.value = packetValue, .size = packetSize, .string = STRINGIFY (packetType)}\n");
for name,id,size in zip (packetsName, packetsId, packetsSize):
    f.write ("    REGISTER_PACKET_TYPE_ENTRY (%s, %d, %d),\n" % (name, id, size));

f.write ("    #undef REGISTER_PACKET_TYPE_ENTRY\n};");
"""

f.close ();
fpy.close ();

print "The structure has been written to : ";
print "%s" % (os.getcwd() + "\\PacketType.h");
print "%s" % (os.getcwd() + "\\PacketType.py");
