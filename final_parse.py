#!/usr/bin/env python3

with open("test_output.ntdf.tdf", "rb") as f:
    data = f.read()

print("CORRECT NanoTDF Parsing (accounting for KAS identifier)")
print("=" * 60)

# Let's manually parse byte by byte
print("\nManual byte-by-byte parsing:")
print(f"0x0000-0x0002: Magic+Version: {data[0:3].hex()} = 'L1L'")
print(f"0x0003: KAS Protocol Enum: 0x{data[3]:02x}")

# WAIT! The Protocol Enum 0x10 means:
# - Protocol: 0x0 (http)
# - Identifier: 0x1 (2 bytes)
# BUT maybe the SDK doesn't separate it properly?

# Let me check what OpenTDFKit's parser is seeing
print("\n" + "=" * 60)
print("What OpenTDFKit parser expects vs what otdfctl generates:\n")

# The actual data shows:
# 0x03: 10 (protocol enum)
# 0x04: 13 (body length = 19 decimal)  
# 0x05-0x17: "10.0.0.138:8080/kas" (19 bytes)
# 0x18-0x19: "65 31" = "e1" 

# So at 0x1A (26) we should have the ephemeral key length
# BUT the next bytes are: 00 01 02 00 68 2a ...

print("At offset 0x18 (24): {:02x} {:02x} = '{}'".format(data[0x18], data[0x19], data[0x18:0x1a].decode()))
print("At offset 0x1A (26): {:02x} = ephemeral key length?".format(data[0x1a]))

# Wait, 0x65 = 101 decimal! That's at offset 0x18!
print("\n0x18: {:02x} = {} decimal (this is where OpenTDFKit sees 101!)".format(data[0x18], data[0x18]))

print("\n" + "=" * 60)
print("THE ISSUE:")
print("- OpenTDFKit doesn't account for the 2-byte KAS identifier")
print("- It reads byte at 0x18 (value 0x65 = 101) as ephemeral key length")
print("- This causes it to read 101 bytes starting from 0x19")
print("- otdfctl includes a 2-byte identifier in the KAS Resource Locator")
print("- OpenTDFKit's parser doesn't handle the identifier field")
