data = bytes.fromhex("3100010200682a3035f5d73c9439c17b17d96ec4c8591094cc9a2aa41aec39f5ce502e9a1103510d530dfb8de85a2712a6d233d865f658a93ab25f9e1b704f72a9b9383b26c86f995a7a72a7a6f0e46f7d5da8ad0c47ed18d3b34843a51fd9241e4359c227")

print("Parsing 101-byte ephemeral key field:")
print("=" * 40)

# First 34 bytes might be a wrapped P-256 key
first_part = data[:34]
print(f"\nFirst 34 bytes:")
print(f"  {first_part.hex(' ')}")

# Check if byte 5 (0x68) could be a length field
if data[4] == 0x00 and data[5] == 0x68:
    print(f"\n  Bytes 4-5: 0x0068 = {0x68} decimal")
    print(f"  Could be a length field for remaining data")
    print(f"  Remaining after byte 6: {len(data) - 6} bytes")

# Last 67 bytes
last_67 = data[-67:]
print(f"\nLast 67 bytes (P-521 size):")
print(f"  First byte: 0x{last_67[0]:02x}")

# Last 33 bytes  
last_33 = data[-33:]
print(f"\nLast 33 bytes (P-256 size):")
print(f"  First byte: 0x{last_33[0]:02x}")
print(f"  {last_33.hex(' ')}")

# Check for any 0x02 or 0x03 markers
print(f"\nSearching for EC key markers (0x02 or 0x03):")
for i, b in enumerate(data):
    if b in [0x02, 0x03]:
        print(f"  Found 0x{b:02x} at offset {i}, {len(data)-i} bytes remaining")
