#!/usr/bin/env python3

# Let's look at the entire NanoTDF structure more carefully
with open("test_output.ntdf.tdf", "rb") as f:
    data = f.read()

print("Full NanoTDF Structure Analysis")
print("=" * 60)

offset = 0

# Magic and version
magic = data[0:2]
version = data[2]
print(f"0x{offset:04x}: Magic: {magic.hex()} Version: 0x{version:02x}")
offset = 3

# KAS Resource Locator
kas_protocol = data[offset]
print(f"\n0x{offset:04x}: KAS Resource Locator")
print(f"       Protocol Enum: 0x{kas_protocol:02x}")
print(f"         Protocol (bits 3-0): 0x{kas_protocol & 0x0F:x}")
print(f"         Identifier (bits 7-4): 0x{(kas_protocol >> 4) & 0x0F:x}")
offset += 1

kas_body_len = data[offset]
print(f"       Body Length: {kas_body_len}")
offset += 1

kas_body = data[offset:offset+kas_body_len]
print(f"       Body: '{kas_body.decode('ascii', errors='ignore')}'")
offset += kas_body_len

# Check if KAS has identifier
kas_id_type = (kas_protocol >> 4) & 0x0F
id_sizes = {0: 0, 1: 2, 2: 8, 3: 32}
kas_id_size = id_sizes.get(kas_id_type, 0)

if kas_id_size > 0:
    kas_id = data[offset:offset+kas_id_size]
    print(f"       Identifier ({kas_id_size} bytes): {kas_id.hex()}")
    offset += kas_id_size

print(f"\n0x{offset:04x}: Next field starts here")
print(f"       Remaining bytes: {len(data) - offset}")

# What if the ephemeral key field ALSO contains a Resource Locator?
print("\n" + "=" * 60)
print("Hypothesis: Ephemeral Key field contains a Resource Locator")

eph_len = data[offset]
print(f"0x{offset:04x}: Ephemeral Key Length: {eph_len}")
offset += 1

eph_data = data[offset:offset+eph_len]
print(f"0x{offset:04x}: Ephemeral Key Data ({eph_len} bytes)")

# Try to parse as Resource Locator
eph_offset = 0
eph_protocol = eph_data[eph_offset]
print(f"       Byte 0: 0x{eph_protocol:02x}")
print(f"         If Protocol Enum:")
print(f"           Protocol: 0x{eph_protocol & 0x0F:x}")
print(f"           Identifier type: 0x{(eph_protocol >> 4) & 0x0F:x}")

# The ephemeral key should just be a compressed EC public key
# Let's check if specific offsets match P-256 key patterns
print("\n" + "=" * 60)
print("Checking for P-256 key at various offsets in ephemeral field:")

for test_offset in [0, 1, 2, 33, 34, 68]:
    if test_offset + 33 <= len(eph_data):
        test_key = eph_data[test_offset:test_offset+33]
        marker = test_key[0]
        print(f"  Offset {test_offset}: First byte = 0x{marker:02x}", end="")
        if marker in [0x02, 0x03]:
            print(" ✓ Valid EC marker")
        else:
            print("")
