data = bytes.fromhex("3100010200682a3035f5d73c9439c17b17d96ec4c8591094cc9a2aa41aec39f5ce502e9a1103510d530dfb8de85a2712a6d233d865f658a93ab25f9e1b704f72a9b9383b26c86f995a7a72a7a6f0e46f7d5da8ad0c47ed18d3b34843a51fd9241e4359c227")

print(f"Total length: {len(data)} bytes")
print(f"First 10 bytes: {data[:10].hex(' ')}")

# Check for potential EC keys at different offsets
for offset in [0, 5, 34, 68]:
    if offset < len(data):
        byte = data[offset]
        remaining = len(data) - offset
        print(f"\nOffset {offset}: byte=0x{byte:02x}, remaining={remaining} bytes")
        if remaining == 33:
            print(f"  -> Could be P-256 key")
        elif remaining == 67:
            print(f"  -> Could be P-521 key")
        if byte in [0x02, 0x03]:
            print(f"  -> Has EC compressed key marker")
            
# Specifically check offset 34 (101 - 67 = 34)
if len(data) >= 34 + 67:
    potential_p521 = data[34:34+67]
    print(f"\nPotential P-521 key at offset 34:")
    print(f"  First byte: 0x{potential_p521[0]:02x}")
    print(f"  Length: {len(potential_p521)}")
    if potential_p521[0] in [0x02, 0x03]:
        print(f"  -> Valid EC compressed key marker!")
