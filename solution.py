"""
Solution for https://mic.hael.xyz/cbc-noauth
"""


def xor(b1, b2):
    if len(b1) != len(b2):
        raise TypeError()
    return bytes(b1[i] ^ b2[i] for i in range(len(b1)))


# receive input
iv_str = input("IV: ")
etok_str = input("Encrypted token: ")
iv = bytes.fromhex(iv_str)
etok = bytes.fromhex(etok_str)
pt = b'{"time_created": "2024-09-17 23:57:40.306735", "user_name": "guest"}'

# change the username part to admin. this overwrites previous bytes which make
# the JSON unparsable, so we'll have to fix that later
dec1 = xor(etok[-32:-16], pt[-16:])
want1 = b'_name": "admin"}'
ct2 = xor(dec1, want1)
print("iv:", iv.hex())
new_etok = etok[:-32] + ct2 + etok[-16:]
print("new:", new_etok.hex())
print("")

# prompt the user for the decrypted version of our modified token. do the same
# process again to fix the bytes we overwrote. this will also overwrite some
# bytes, but it will be in the timestamp so the JSON will still parse
new_pt_str = input("New plaintext: ")
new_pt = eval("b'" + new_pt_str + "'")
dec2 = xor(new_etok[-48:-32], new_pt[-32:-16])
want2 = b'0.306735", "user'
ct3 = xor(dec2, want2)
print("iv:", iv.hex())
new_etok2 = new_etok[:-48] + ct3 + new_etok[-32:]
print("new:", (new_etok2).hex())
