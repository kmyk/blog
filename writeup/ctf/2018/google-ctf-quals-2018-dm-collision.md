---
layout: post
title: "Google Capture The Flag 2018 (Quals): DM Collision"
date: "2018-06-27T12:06+09:00"
tags: [ "ctf", "writeup", "google-ctf", "crypto", "dea", "fixed-point", "weak-key", "davies-meyer", "one-way-compression-function" ]
"target_url": [ "https://ctftime.org/event/623" ]
---

## note

この記事は次を見た後に書いた。

<blockquote class="twitter-tweet" data-conversation="none" data-lang="ja"><p lang="ja" dir="ltr">DM COLLISION、これを見て、100億連ガチャを回してそのままにして寝ていたら衝突してた……。信じてもっと早めに試していれば……。<br>block cipher - What is the fixed point attribute of DES (when used with weak-keys) - Cryptography Stack Exchange<a href="https://t.co/rGM5SrzwxQ">https://t.co/rGM5SrzwxQ</a> <a href="https://t.co/9gPzfmwLYH">pic.twitter.com/9gPzfmwLYH</a></p>&mdash; kusanoさん@がんばらない (@kusano_k) <a href="https://twitter.com/kusano_k/status/1011120618228539392?ref_src=twsrc%5Etfw">2018年6月25日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

参照されてるページは私も見た記憶があるが、回答がなくコメントだけだったので素通りしてしまっていた。反省したい。

## problem

S-boxの順序が次のように変更されている[DES](https://web.archive.org/web/20160226035739/http://ruffnex.oc.to/kenji/xrea/des.txt)を用いて、[Davies-Meyer型 one-way compression function](https://en.wikipedia.org/wiki/One-way_compression_function#Davies%E2%80%93Meyer) $F\_k(x) = E\_k(x) \oplus x$ を考える。

```
SBOXES = [S6, S4, S1, S5, S3, S2, S8, S7]
```

次を満たすような $(k\_1, x\_1), (k\_2, x\_2), (k\_3, x\_3)$ を提出せよ:

1.  衝突: $(k\_1, x\_1) \ne (k\_2, x\_2)$ かつ $F\_{k\_1}(x\_1) = F\_{k\_2}(x\_2)$
2.  原像: $F\_{k\_3}(x\_3) = 0$

## solution

### 衝突

DESの鍵にはparity bitというものがあり、これは歴史的なもので現在ではたいてい無視される ([参考](https://crypto.stackexchange.com/questions/34199/purpose-of-des-parity-bits))。
具体的には各byteのLSB。例としては次を実行せよ:

```
#!/usr/bin/env python3
import Crypto.Cipher.DES  # https://pypi.org/project/pycrypto/

key1 = "01234567"
des1 = Crypto.Cipher.DES.new(key1, Crypto.Cipher.DES.MODE_ECB)

key2 = "10325476"
des2 = Crypto.Cipher.DES.new(key2, Crypto.Cipher.DES.MODE_ECB)

plaintext = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliq"
assert des2.decrypt(des1.encrypt(plaintext)) == plaintext
```

これはS-boxの順序には依存しないため同様にすればよい。

### 原像

これはDESの不動点を求めろという問題である。
$F\_k(x) = E\_k(x) \oplus x = 0$ を変形すると $E\_k(x) = x$ なため。
検索すると「weak-keyなら$2^{32}$個の不動点があるよ」とでてくる ([SO](https://crypto.stackexchange.com/questions/20896/what-is-the-fixed-point-attribute-of-des-when-used-with-weak-keys))。
これもS-boxの順序には依存しない。
全空間は$2^{64}$なので$10^9$個ぐらい試せばよくて、これは十分可能。
`not_des.py` をそのまま使うと$100$個/秒と厳しいが、Cで実装して$100$倍速と仮定、さらに並列化で例えば$32$倍速と仮定すると、これは$1$時間程度で結果が出ると予想できる (試してはいない)。

不動点が$2^{32}$個というのの説明があるのはこれ: [The Real Reason for Rivest’s Phenomenon | SpringerLink](https://link.springer.com/chapter/10.1007%2F3-540-39799-X_42)。
たった$2$ページと読みやすいので読んで。
概要は以下。
DESはFeistel構造なのでそのround関数を$f$があって、平文が$M\_0, M\_1$と分割され $M\_{i+1} = M\_{i-1} \oplus f(K\_i, M\_i)$ と処理されて$M\_{17}, M\_{16}$が暗号文。
weak-keyを選べば内部鍵$K\_i$はすべて一致し、加えて $M\_8 = M\_9$ なら$M\_7 = M\_{10}, M\_6 = M\_{11}, \dots$と伝播して平文と暗号文が一致する。
さて$M\_8 = M\_9$となるような入力$Y$がいくつあるかだが、内部状態$M\_8, M\_9 \in 2^{32}$なので(ぞろ目の出る確率のように見て)確率$\frac{1}{2^{32}}$で一致し、入力は$Y \in 2^{64}$。
よって不動点はおよそ$2^{32}$個以上あると推測できる。
