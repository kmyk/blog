---
layout: post
redirect_from:
  - /blog/2017/06/22/boston-key-party-ctf-2016-des-ofb/
date: "2017-06-22T04:38:19+09:00"
tags: [ "ctf", "writeup", "crypto", "boston-key-party-ctf", "des", "ofb" ]
"target_url": [ "https://github.com/ctfs/write-ups-2016/tree/master/boston-key-party-2016/crypto/des-ofb-2" ]
---

# Boston Key Party CTF : des ofb

guessingが無理だったのでwriteupを見ました。

## solution

与えられた `des-ofb.py` は十分に単純で脆弱性はなさそう。
しかし `ciphertext` を `xxd` すると以下のように規則性を感じる。
これをもとに、 `plaintext` は全てASCIIであると仮定していい感じにguessingすると解ける。

```
$ xxd ciphertext | head -n 32
00000000: 702b 7bef 9327 53d3 4313 5c5b 4116 4357  p+{..'S.C.\[A.CW
00000010: 0426 3ea1 d67f 1bdd 4513 5b47 1542 5f5d  .&>.....E.[G.B_]
00000020: 0435 2ee8 857f 1ad3 5f09 3863 5d53 4350  .5......_.8c]SCP
00000030: 4136 7baa 8262 009c 7f5c 5058 5044 1751  A6{..b...\PXPD.Q
00000040: 4a64 2fe5 932b 1ed5 5f57 1240 5a16 444d  Jd/..+.._W.@Z.DM
00000050: 4222 3eff fc5f 1bd9 1160 5e5d 5b51 4418  B">.._...`^][QD.
00000060: 452a 3fad b779 01d3 4640 125b 5316 584d  E*?..y..F@.[S.XM
00000070: 5036 3aea 9364 06cf 1175 5d46 4143 595d  P6:..d...u]FACY]
00000080: 084e 14ff d67f 1c9c 4552 5951 1577 4555  .N......ERYQ.wEU
00000090: 5764 3aea 9762 1dcf 4513 5314 6653 5618  Wd:..b..E.S.fSV.
000000a0: 4b22 7bf9 8464 06de 5d56 4118 3f77 595c  K"{..d..]VA.?wY\
000000b0: 0426 22ad 997b 03d3 425a 5c53 1553 595c  .&"..{..BZ\S.SY\
000000c0: 0430 33e8 9b31 53c8 5e13 565d 501a 174c  .03..1S.^.V]P..L
000000d0: 4b64 28e1 936e 03b6 7f5c 1259 5a44 5203  Kd(..n...\.YZDR.
000000e0: 0425 35e9 d669 0a9c 5013 4158 5053 4714  .%5..i..P.AXPSG.
000000f0: 0430 34ad 856a 0a9c 4656 1251 5b52 3d6c  .04..j..FV.Q[R=l
00000100: 4c21 7bc5 936a 01c8 1c52 515c 501a 1759  L!{..j...RQ\P..Y
00000110: 4a20 7bf9 9e6e 53c8 595c 4747 5458 5318  J {..nS.Y\GGTXS.
00000120: 6a25 2ff8 846a 1f9c 425b 5d57 5e45 3d6c  j%/..j..B[]W^E=l
00000130: 4c25 2fad b067 16cf 5913 5b47 155e 5251  L%/..g..Y.[G.^RQ
00000140: 5664 2fe2 c92b 54e8 5840 1255 1555 5856  Vd/..+T.X@.U.UXV
00000150: 5731 36e0 977f 1ad3 5f39 7651 4359 424c  W16....._9vQCYBL
00000160: 483d 7bf9 992b 11d9 1144 5b47 5d53 5316  H={..+...D[G]SS.
00000170: 0410 34ad 9262 1690 1147 5d14 465a 525d  ..4..b...G].FZR]
00000180: 5468 51d9 992b 00d0 5456 4218 1546 524a  ThQ..+..TVB..FRJ
00000190: 472c 3ae3 956e 53c8 5e13 7646 5057 5a03  G,:..nS.^.vFPWZ.
000001a0: 0425 22e8 da2b 07d4 5441 5713 4616 4350  .%"..+..TAW.F.CP
000001b0: 4164 29f8 9427 79fa 5e41 125d 5b16 4350  Ad)..'y.^A.][.CP
000001c0: 4530 7bfe 9a6e 16cc 115c 5414 5153 564c  E0{..n...\T.QSVL
000001d0: 4c68 7bfa 9e6a 079c 5541 5755 5845 1755  Lh{..j..UAWUXE.U
000001e0: 453d 7bee 9966 1690 3b64 5a51 5b16 405d  E={..f..;dZQ[.@]
000001f0: 042c 3afb 932b 00d4 4455 5458 5052 1757  .,:..+..DUTXPR.W
```

なぜこうなるかというと、鍵$K$での暗号化関数$E\_K$が$E\_K(E\_K(P)) = P$となるような弱い鍵$K$が存在するため。
たった$4$つしかないため通常は問題にならないが、わざわざこれを選んで使用したらしい。
実際[Weak key in DES](https://en.wikipedia.org/wiki/Weak_key#Weak_keys_in_DES)として知られるもののひとつである$\mathtt{0xE0E0E0E0F1F1F1F1}$を試すと、これが鍵であったことが分かる。

## implementation

``` python
#!/usr/bin/env python3
import sys

with open('ciphertext') as fh:
    ciphertext = fh.buffer.read()

isallowed = lambda c: c == 10 or c == 13 or 32 <= c < 125
candidates = [ [] for _ in range(16) ]
for x in range(16):
    for k in range(256):
        for i in range(x, len(ciphertext), 16):
            if not isallowed(k ^ ciphertext[i]): # not ascii
                break
        else:
            candidates[x] += [ k ]
candidates = tuple(map(tuple, candidates))
assert candidates == (
    (34, 36, 37, 38, 39),
    (68,),
    (91,),
    (138, 141),
    (246,),
    (11, 12),
    (94,),
    (187, 188),
    (),
    (),
    (),
    (51, 52),
    (53,),
    (51, 52, 53, 54, 55),
    (48, 55),
    (56,),
)

def decrypt(key):
    plaintext = []
    for i, c in enumerate(ciphertext):
        plaintext += [ key[i % 16] ^ c ]
    return bytes(plaintext)

# key = [ 34, 68, 91, 138, 246, 11, 94, 187, 0, 0, 0, 51, 53, 51, 48, 56 ]
#            q   u    e     s   t    i    o    n
#        C   T   F    {                                             B   K   P
key = [ 36, 68, 91, 141,  246, 11, 115, 188,  49, 51, 50, 52,  53, 54, 55, 56 ]
sys.stdout.buffer.write(decrypt(key))
```
