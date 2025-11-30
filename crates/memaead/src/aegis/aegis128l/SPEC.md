# AEGIS-128L Specification

Source: draft-irtf-cfrg-aegis-aead-18

## Parameters

- Key: 128 bits (16 bytes)
- Nonce: 128 bits (16 bytes)
- State: 1024 bits = 8 x 128-bit blocks {S0, ..., S7}
- Input block: 256 bits (32 bytes)
- Tag: 128 or 256 bits

## Constants

```
C0 = { 0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d,
       0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 }

C1 = { 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1,
       0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd }
```

## AESRound(in, rk)

Single AES encryption round: SubBytes + ShiftRows + MixColumns + AddRoundKey(rk)

In x86_64: `_mm_aesenc_si128(in, rk)`

## Update(M0, M1)

Core state update function. Takes two 128-bit blocks.

```
S'0 = AESRound(S7, S0 ^ M0)
S'1 = AESRound(S0, S1)
S'2 = AESRound(S1, S2)
S'3 = AESRound(S2, S3)
S'4 = AESRound(S3, S4 ^ M1)
S'5 = AESRound(S4, S5)
S'6 = AESRound(S5, S6)
S'7 = AESRound(S6, S7)

S0..S7 = S'0..S'7
```

## Init(key, nonce)

```
S0 = key ^ nonce
S1 = C1
S2 = C0
S3 = C1
S4 = key ^ nonce
S5 = key ^ C0
S6 = key ^ C1
S7 = key ^ C0

Repeat(10, Update(nonce, key))
```

## Absorb(ai)

Absorbs 256-bit block of associated data.

```
t0, t1 = Split(ai, 128)
Update(t0, t1)
```

## Enc(xi)

Encrypts 256-bit plaintext block.

```
z0 = S1 ^ S6 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(xi, 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(t0, t1)

return out0 || out1
```

## Dec(ci)

Decrypts 256-bit ciphertext block.

```
z0 = S1 ^ S6 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(ci, 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

Update(out0, out1)  // Uses PLAINTEXT, not ciphertext!

return out0 || out1
```

## DecPartial(cn)

Decrypts last partial block (< 256 bits).

```
z0 = S1 ^ S6 ^ (S2 & S3)
z1 = S2 ^ S5 ^ (S6 & S7)

t0, t1 = Split(ZeroPad(cn, 256), 128)
out0 = t0 ^ z0
out1 = t1 ^ z1

xn = Truncate(out0 || out1, |cn|)

v0, v1 = Split(ZeroPad(xn, 256), 128)
Update(v0, v1)

return xn
```

## Finalize(ad_len_bits, msg_len_bits)

```
t = S2 ^ (LE64(ad_len_bits) || LE64(msg_len_bits))

Repeat(7, Update(t, t))

if tag_len == 128:
    tag = S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6
else:  // 256 bits
    tag = (S0 ^ S1 ^ S2 ^ S3) || (S4 ^ S5 ^ S6 ^ S7)

return tag
```

## Encrypt(msg, ad, key, nonce)

```
Init(key, nonce)

ct = {}

ad_blocks = Split(ZeroPad(ad, 256), 256)
for ai in ad_blocks:
    Absorb(ai)

msg_blocks = Split(ZeroPad(msg, 256), 256)
for xi in msg_blocks:
    ct = ct || Enc(xi)

tag = Finalize(|ad|, |msg|)
ct = Truncate(ct, |msg|)

return ct, tag
```

## Decrypt(ct, tag, ad, key, nonce)

```
Init(key, nonce)

msg = {}

ad_blocks = Split(ZeroPad(ad, 256), 256)
for ai in ad_blocks:
    Absorb(ai)

ct_blocks = Split(ct, 256)
cn = Tail(ct, |ct| mod 256)

for ci in ct_blocks:
    msg = msg || Dec(ci)

if cn is not empty:
    msg = msg || DecPartial(cn)

expected_tag = Finalize(|ad|, |msg|)

if CtEq(tag, expected_tag) is False:
    erase msg
    return error
else:
    return msg
```

## Required Intrinsics Operations

- `zero()` - create zero block
- `load(&[u8; 16])` - load bytes into block
- `store(&mut [u8; 16])` - store block to bytes
- `xor(&self, &other)` - bitwise XOR
- `and(&self, &other)` - bitwise AND (for z0, z1 computation)
- `aes_enc(&self, rk)` - AES encryption round

## Security Requirements

- Nonce MUST NOT be reused for a given key
- Tag comparison MUST be constant-time
- On auth failure: decrypted message MUST be zeroized before return

## Test Vectors

### A.1 AESRound Test Vector

```
in  : 000102030405060708090a0b0c0d0e0f
rk  : 101112131415161718191a1b1c1d1e1f
out : 7a7b4e5638782546a8c0477a3b813f43
```

### A.2.1 Update Test Vector

```
Before:
S0 : 9b7e60b24cc873ea894ecc07911049a3
S1 : 330be08f35300faa2ebf9a7b0d274658
S2 : 7bbd5bd2b049f7b9b515cf26fbe7756c
S3 : c35a00f55ea86c3886ec5e928f87db18
S4 : 9ebccafce87cab446396c4334592c91f
S5 : 58d83e31f256371e60fc6bb257114601
S6 : 1639b56ea322c88568a176585bc915de
S7 : 640818ffb57dc0fbc2e72ae93457e39a

M0 : 033e6975b94816879e42917650955aa0
M1 : fcc1968a46b7e97861bd6e89af6aa55f

After:
S0 : 596ab773e4433ca0127c73f60536769d
S1 : 790394041a3d26ab697bde865014652d
S2 : 38cf49e4b65248acd533041b64dd0611
S3 : 16d8e58748f437bfff1797f780337cee
S4 : 9689ecdf08228c74d7e3360cca53d0a5
S5 : a21746bb193a569e331e1aa985d0d729
S6 : 09d714e6fcf9177a8ed1cde7e3d259a6
S7 : 61279ba73167f0ab76f0a11bf203bdff
```

### A.2.2 Test Vector 1 (16-byte msg, no ad)

```
key    : 10010000000000000000000000000000
nonce  : 10000200000000000000000000000000
ad     : (empty)
msg    : 00000000000000000000000000000000
ct     : c1c0e58bd913006feba00f4b3cc3594e
tag128 : abe0ece80c24868a226a35d16bdae37a
tag256 : 25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4
```

### A.2.3 Test Vector 2 (empty msg, no ad)

```
key    : 10010000000000000000000000000000
nonce  : 10000200000000000000000000000000
ad     : (empty)
msg    : (empty)
ct     : (empty)
tag128 : c2b879a67def9d74e6c14f708bbcc9b4
tag256 : 1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d
```

### A.2.4 Test Vector 3 (32-byte msg, 8-byte ad)

```
key    : 10010000000000000000000000000000
nonce  : 10000200000000000000000000000000
ad     : 0001020304050607
msg    : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
ct     : 79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84
tag128 : cc6f3372f6aa1bb82388d695c3962d9a
tag256 : 022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3
```

### A.2.5 Test Vector 4 (13-byte msg, 8-byte ad) - partial block

```
key    : 10010000000000000000000000000000
nonce  : 10000200000000000000000000000000
ad     : 0001020304050607
msg    : 000102030405060708090a0b0c0d
ct     : 79d94593d8c2119d7e8fd9b8fc77
tag128 : 5c04b3dba849b2701effbe32c7f0fab7
tag256 : 86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac
```

### A.2.6 Test Vector 5 (longer msg and ad)

```
key    : 10010000000000000000000000000000
nonce  : 10000200000000000000000000000000
ad     : 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829
msg    : 101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637
ct     : b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10
tag128 : 7542a745733014f9474417b337399507
tag256 : b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98
```

### A.2.7 Test Vector 6 - MUST FAIL (wrong key)

```
key    : 10000200000000000000000000000000
nonce  : 10010000000000000000000000000000
ad     : 0001020304050607
ct     : 79d94593d8c2119d7e8fd9b8fc77
tag128 : 5c04b3dba849b2701effbe32c7f0fab7
```

### A.2.8 Test Vector 7 - MUST FAIL (modified ct)

```
key    : 10010000000000000000000000000000
nonce  : 10000200000000000000000000000000
ad     : 0001020304050607
ct     : 79d94593d8c2119d7e8fd9b8fc78
tag128 : 5c04b3dba849b2701effbe32c7f0fab7
```

### A.2.9 Test Vector 8 - MUST FAIL (modified ad)

```
key    : 10010000000000000000000000000000
nonce  : 10000200000000000000000000000000
ad     : 0001020304050608
ct     : 79d94593d8c2119d7e8fd9b8fc77
tag128 : 5c04b3dba849b2701effbe32c7f0fab7
```

### A.2.10 Test Vector 9 - MUST FAIL (modified tag)

```
key    : 10010000000000000000000000000000
nonce  : 10000200000000000000000000000000
ad     : 0001020304050607
ct     : 79d94593d8c2119d7e8fd9b8fc77
tag128 : 6c04b3dba849b2701effbe32c7f0fab8
```
