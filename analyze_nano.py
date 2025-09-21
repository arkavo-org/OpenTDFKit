#!/usr/bin/env python3
import sys

with open("test_output.ntdf.tdf", "rb") as f:
    data = f.read()

print("NanoTDF Structure Analysis")
print("=" * 50)

offset = 0

# Magic and version
magic = data[0:2]
version = data[2]
print(f"0x{offset:04x}: Magic: {magic.hex()} ('{magic.decode('ascii', errors='ignore')}')")
print(f"0x{offset+2:04x}: Version: 0x{version:02x} ('{chr(version)}')")
offset = 3

# KAS Resource Locator
kas_protocol = data[offset]
print(f"\n0x{offset:04x}: KAS Protocol: 0x{kas_protocol:02x}")
offset += 1

kas_body_len = data[offset]
print(f"0x{offset:04x}: KAS Body Length: {kas_body_len}")
offset += 1

kas_body = data[offset:offset+kas_body_len]
print(f"0x{offset:04x}: KAS Body: '{kas_body.decode('ascii', errors='ignore')}'")
offset += kas_body_len

# Ephemeral Public Key
eph_key_len = data[offset]
print(f"\n0x{offset:04x}: Ephemeral Key Length: {eph_key_len}")
offset += 1

eph_key = data[offset:offset+eph_key_len]
print(f"0x{offset:04x}: Ephemeral Key (first 32 bytes):")
print(f"       {eph_key[:32].hex(' ')}")
if eph_key_len == 33:
    print(f"       -> Looks like secp256r1 (P-256)")
elif eph_key_len == 49:
    print(f"       -> Looks like secp384r1 (P-384)")
elif eph_key_len == 67:
    print(f"       -> Looks like secp521r1 (P-521)")
offset += eph_key_len

# Policy Binding Config
policy_binding = data[offset]
print(f"\n0x{offset:04x}: Policy Binding: 0x{policy_binding:02x}")
ecdsa_binding = (policy_binding & 0x80) != 0
eph_curve = policy_binding & 0x07
print(f"       ECDSA Binding: {ecdsa_binding}")
print(f"       Ephemeral Curve: 0x{eph_curve:02x}")
offset += 1

# Payload Signature Config
payload_config = data[offset]
print(f"\n0x{offset:04x}: Payload Config: 0x{payload_config:02x}")
has_signature = (payload_config & 0x80) != 0
sig_curve = (payload_config >> 4) & 0x07
cipher = payload_config & 0x0F
print(f"       Has Signature: {has_signature}")
print(f"       Signature Curve: 0x{sig_curve:02x}")
print(f"       Symmetric Cipher: 0x{cipher:02x}")
offset += 1

print(f"\n0x{offset:04x}: Remaining bytes: {len(data) - offset}")
print(f"       Next 32 bytes: {data[offset:offset+32].hex(' ')}")
