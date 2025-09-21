#!/usr/bin/env python3

# Analyze the 101-byte ephemeral key field for Resource Locator structure
data = bytes.fromhex("3100010200682a3035f5d73c9439c17b17d96ec4c8591094cc9a2aa41aec39f5ce502e9a1103510d530dfb8de85a2712a6d233d865f658a93ab25f9e1b704f72a9b9383b26c86f995a7a72a7a6f0e46f7d5da8ad0c47ed18d3b34843a51fd9241e4359c227")

print("Analyzing 101-byte field for Resource Locator structure")
print("=" * 60)
print(f"Total length: {len(data)} bytes\n")

# Check if this could be a Resource Locator
print("Byte 0: 0x{:02x}".format(data[0]))

# Protocol Enum analysis (bits 3-0 for protocol, bits 7-4 for identifier size)
protocol = data[0] & 0x0F
identifier_type = (data[0] >> 4) & 0x0F

protocol_map = {
    0x0: "http",
    0x1: "https", 
    0x2: "unreserved",
    0xF: "Shared Resource Directory"
}

identifier_map = {
    0x0: "None (0 bytes)",
    0x1: "2 bytes",
    0x2: "8 bytes",
    0x3: "32 bytes"
}

print(f"If byte 0 is Protocol Enum:")
print(f"  Protocol (bits 3-0): 0x{protocol:x} = {protocol_map.get(protocol, 'unknown')}")
print(f"  Identifier (bits 7-4): 0x{identifier_type:x} = {identifier_map.get(identifier_type, 'unknown')}")

# If it's a Resource Locator, next byte should be body length
if len(data) > 1:
    body_length = data[1]
    print(f"\nByte 1 (potential body length): {body_length}")
    
    if body_length > 0 and body_length < len(data) - 2:
        # Try to extract the body
        body = data[2:2+body_length]
        print(f"Potential body ({body_length} bytes): {body.hex()}")
        
        # Try to decode as string
        try:
            body_str = body.decode('utf-8')
            print(f"  As string: '{body_str}'")
        except:
            print(f"  Not valid UTF-8")
        
        # Calculate where identifier would start
        identifier_start = 2 + body_length
        
        # Check identifier size
        identifier_sizes = {0x0: 0, 0x1: 2, 0x2: 8, 0x3: 32}
        expected_id_size = identifier_sizes.get(identifier_type, 0)
        
        if expected_id_size > 0:
            print(f"\nIdentifier (expected {expected_id_size} bytes at offset {identifier_start}):")
            if identifier_start + expected_id_size <= len(data):
                identifier = data[identifier_start:identifier_start + expected_id_size]
                print(f"  {identifier.hex()}")
                
                # Check what comes after
                after_locator = identifier_start + expected_id_size
                print(f"\nAfter Resource Locator (offset {after_locator}):")
                remaining = data[after_locator:]
                print(f"  Remaining bytes: {len(remaining)}")
                if len(remaining) == 33:
                    print(f"  ✓ Exactly 33 bytes remain (P-256 key size!)")
                    print(f"  First byte: 0x{remaining[0]:02x}")
                    if remaining[0] in [0x02, 0x03]:
                        print(f"  ✓ Starts with compressed EC key marker!")
                elif len(remaining) == 67:
                    print(f"  ✓ Exactly 67 bytes remain (P-521 key size!)")

print("\n" + "=" * 60)
print("Alternative interpretation: Just check if last 33 bytes are a key")
last_33 = data[-33:]
print(f"Last 33 bytes: {last_33.hex()}")
print(f"First byte of last 33: 0x{last_33[0]:02x}")
if last_33[0] in [0x02, 0x03]:
    print("  ✓ Valid compressed EC key marker!")
else:
    print("  ✗ Does not start with compressed EC key marker (0x02/0x03)")
