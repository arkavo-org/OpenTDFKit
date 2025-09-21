data = bytes.fromhex("3100010200682a3035f5d73c9439c17b17d96ec4c8591094cc9a2aa41aec39f5ce502e9a1103510d530dfb8de85a2712a6d233d865f658a93ab25f9e1b704f72a9b9383b26c86f995a7a72a7a6f0e46f7d5da8ad0c47ed18d3b34843a51fd9241e4359c227")

print("Checking for P-256 key in 101-byte ephemeral field:")
print("=" * 50)

# otdfctl only supports secp256r1 (33 bytes)
# The field might be: metadata + 33-byte key

# Check last 33 bytes
last_33 = data[-33:]
print(f"\nLast 33 bytes (P-256 size):")
print(f"  {last_33.hex(' ')}")
print(f"  First byte: 0x{last_33[0]:02x}")

# Check at offset 68 (101 - 33 = 68)
if len(data) >= 68 + 33:
    at_68 = data[68:]
    print(f"\nAt offset 68 (33 bytes):")
    print(f"  {at_68.hex(' ')}")
    print(f"  First byte: 0x{at_68[0]:02x}")

# The structure might be:
# - Some header/metadata
# - The actual P-256 ephemeral public key (33 bytes)
# Total: 101 bytes

print(f"\nConclusion:")
print(f"  otdfctl only supports secp256r1 (P-256)")
print(f"  The 101-byte field likely contains:")
print(f"    - 68 bytes of metadata/wrapping")
print(f"    - 33 bytes of P-256 key material")
