#!/usr/bin/env python3

with open("test_output.ntdf.tdf", "rb") as f:
    data = f.read()

print("Correct NanoTDF Parsing")
print("=" * 60)

offset = 0

# Magic and version (3 bytes)
magic = data[0:2]
version = data[2]
print(f"0x{offset:04x}: Magic: {magic.hex()} Version: 0x{version:02x}")
offset = 3

# KAS Resource Locator
kas_protocol = data[offset]
protocol = kas_protocol & 0x0F
id_type = (kas_protocol >> 4) & 0x0F
print(f"\n0x{offset:04x}: KAS Protocol Enum: 0x{kas_protocol:02x}")
print(f"       Protocol: 0x{protocol:x} (http)")
print(f"       Identifier type: 0x{id_type:x} (2 bytes)")
offset += 1

kas_body_len = data[offset]
print(f"0x{offset:04x}: KAS Body Length: {kas_body_len}")
offset += 1

kas_body = data[offset:offset+kas_body_len]
print(f"0x{offset:04x}: KAS Body: '{kas_body.decode()}'")
offset += kas_body_len

# KAS has a 2-byte identifier!
if id_type == 1:  # 2 bytes
    kas_id = data[offset:offset+2]
    print(f"0x{offset:04x}: KAS Identifier: {kas_id.hex()} ('{kas_id.decode()}')")
    offset += 2

print(f"\n0x{offset:04x}: After KAS+Identifier, offset is now {offset}")

# NOW comes the ephemeral key
eph_len = data[offset]
print(f"\n0x{offset:04x}: Ephemeral Key Length: {eph_len}")
offset += 1

if eph_len > 0:
    eph_key = data[offset:offset+eph_len]
    print(f"0x{offset:04x}: Ephemeral Key ({eph_len} bytes)")
    print(f"       First 16 bytes: {eph_key[:16].hex(' ')}")
    
    # Check if it's a standard compressed key
    if eph_len in [33, 49, 67]:
        curve = {33: "P-256", 49: "P-384", 67: "P-521"}[eph_len]
        print(f"       ✓ Standard {curve} compressed key size")
        if eph_key[0] in [0x02, 0x03]:
            print(f"       ✓ Valid compressed EC marker: 0x{eph_key[0]:02x}")
    else:
        print(f"       ✗ Non-standard ephemeral key size: {eph_len}")
        
        # Could it contain a Resource Locator?
        if eph_len > 3:
            potential_protocol = eph_key[0]
            potential_body_len = eph_key[1] if len(eph_key) > 1 else 0
            print(f"\n       If this is a Resource Locator:")
            print(f"         Byte 0: 0x{potential_protocol:02x}")
            print(f"           Protocol: 0x{potential_protocol & 0x0F:x}")
            print(f"           Identifier: 0x{(potential_protocol >> 4) & 0x0F:x}")
            print(f"         Byte 1 (body length): {potential_body_len}")
    
    offset += eph_len

print(f"\n0x{offset:04x}: After ephemeral key, offset is {offset}")

# Next should be ECC & Binding Mode
if offset < len(data):
    binding = data[offset]
    print(f"\n0x{offset:04x}: ECC & Binding Mode: 0x{binding:02x}")
    use_ecdsa = (binding & 0x80) != 0
    eph_curve = binding & 0x07
    print(f"       ECDSA: {use_ecdsa}")
    print(f"       Curve: 0x{eph_curve:x}")
