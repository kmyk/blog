---
layout: post
alias: "/blog/2016/08/27/asis-finals-ctf-2015-simple/"
date: "2016-08-27T01:03:28+09:00"
tags: [ "ctf", "writeup", "asis-ctf", "crypto", "xor" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/asis-finals-ctf-2015/crypto/simple" ]
---

# ASIS Cyber Security Contest 2015: simple

これは分からない。解説を見た: <https://kt.pe/blog/2015/10/asis-2015-finals-simple/>。

入力は以下の文字列のみ。

```
110d00_000a0701_1a00_00120812_171b1a171500111a150011_001b_071006001901_0900_787100_00091b00_00130805120f0908_0900_5143594353445602000105_140b0a000b_00021500151e141514_1b00_0a15000b0b0c0b02_1000131117_000f05_0a030000031b0908_001b_101f1c001a1d14_435340424400
```

`_`を空白つまり単語の区切りとして、各文字が$16$進数$2$桁に何らかで変換されて書かれているのかもしれない、というのは推測できる。
これは実際正しくて、各単語ごとに決められた鍵となる$1$文字とのxorが書かれていたようだ。
情報量が少ないので消去法的にも、問題名からしても、xorというのは分からなくもないがつらい。
各単語ごとに鍵というのが特に厳しいのだが、各単語ごとに一箇所の`00`を含むことから推測できたのかもしれない。

各単語ごとに一箇所の`00`を含むため、鍵はprintableなもののみを試せばよい。それでもけっこうつらいので、spell checkerのようなものを試した。
`MD5`や`asis`のようなものは固有名詞であるので無視するとしても、pythonのlibraryとして`nltk`と`enchant`を試したが、どちらも辞書が弱いのか(stemmmingをしても)`prepend`を認識させられなかった。
`wamerican-large`や`iamerican-large`として`apt`で入る辞書には載っていたので頑張ってほしい。

最終的に`the flag is asis concatenate to result of MD5 hash function of asisctf2015 which prepended to opening brace and followed by closing brace!`が復元できる。

``` python
#!/usr/bin/env python3
import string
import binascii

import nltk # with $ python3 -m nltk.downloader words
words = nltk.corpus.words.words
stem = nltk.stem.porter.PorterStemmer().stem

with open('encryted') as fh:
    ciphertext = fh.read().strip()
print(ciphertext)

for w in ciphertext.split('_'):
    y = binascii.unhexlify(w).decode()
    xs = []
    for k in string.printable:
        x = ''
        for c in y:
            c = chr(ord(c) ^ k)
            if c in string.printable:
                x += c
            else:
                x = ''
                break
        if x:
            xs += [x]
    zs = []
    for x in xs:
        if stem(x) in words():
            zs += [x]
    if zs:
        print(w, zs)
    else:
        print(w, xs)
```
