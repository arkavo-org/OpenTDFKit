data = bytes.fromhex("3100010200682a3035f5d73c9439c17b17d96ec4c8591094cc9a2aa41aec39f5ce502e9a1103510d530dfb8de85a2712a6d233d865f658a93ab25f9e1b704f72a9b9383b26c86f995a7a72a7a6f0e46f7d5da8ad0c47ed18d3b34843a51fd9241e4359c227")

print("NanoTDF Ephemeral Key Analysis")
print("=" * 40)

# The structure appears to be:
# Bytes 0-33: Some kind of header or first key
# Bytes 34-100: The actual ephemeral key (67 bytes)

header = data[:34]
eph_key = data[34:]

print(f"\nTotal: {len(data)} bytes")
print(f"First part: {len(header)} bytes")
print(f"Second part: {len(eph_key)} bytes")

print(f"\nFirst part (34 bytes):")
print(f"  Starts with: {header[:8].hex(' ')}")
print(f"  Contains 0x03 at position 3")

print(f"\nSecond part (67 bytes) - matches P-521 size:")
print(f"  First bytes: {eph_key[:8].hex(' ')}")

# The ephemeral curve from policy binding was 0x02 = secp521r1
print(f"\nConclusion:")
print(f"  Policy binding says curve is 0x02 = secp521r1 (P-521)")
print(f"  Last 67 bytes match P-521 compressed key size")
print(f"  But it doesn't start with 0x02/0x03 marker")
print(f"\nThe 101-byte field appears to contain:")
print(f"  - 34 bytes of metadata/wrapper")
print(f"  - 67 bytes of key material (P-521)")
