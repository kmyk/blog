---
layout: post
redirect_from:
  - /blog/2016/08/26/0ctf-2015-oldcrypto/
date: "2016-08-26T14:59:38+09:00"
tags: [ "ctf", "writeup", "0ctf", "crypto", "vigenere-cipher", "kasiski-test" ]
"target_url": [ "https://github.com/ctfs/write-ups-2015/tree/master/0ctf-2015/crypto/oldcrypto" ]
---

# 0CTF 2015 Quals CTF: oldcrypto

解けず。writeupを見た: <https://web.archive.org/web/20150407090556/https://b01lers.net/challenges/0ctf/Old%20cryptography/39/>。

## solution

Vigenere暗号の問題。この暗号をそう呼ぶと知ってしまえば、解き方は知られているのでやるだけになる。

-   [Vigenère cipher - Wikipedia](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
-   [古典暗号 - Vigenere暗号とカシスキー・テスト - ₍₍ (ง ˘ω˘ )ว ⁾⁾ &lt; 暗号楽しいです](http://elliptic-shiho.hatenablog.com/entry/2015/11/12/041637)

Vigenere暗号とは、複数の表を周期的に用いる換字式暗号。
鍵長$l$なら、$i$番目の文字は$i \equiv j \pmod l$な$j$番目の表を用いる。

Vigenere暗号のCaesar暗号と比しての難しさは、ある文字とある文字が同じ表で変換されているのかが分からないことである。
しかしこの困難は、鍵長$l$(かその倍数)が分かれば回避でき、これは表の利用の周期性を用いて解析できる。
具体的には、Kasiskiテストというものが知られる。
十分な長さの暗号分があれば、同様の単語が同様の表で暗号化された部分が出現し、そのような部分文字列の距離は鍵長の倍数である。
つまり、ある程度の長さの部分文字列で複数箇所に出現するものを集めてきて、それらの距離の最大公約数を鍵長と仮定してしまえばよい、というのがこの手法である。
鍵長が判明すれば、Caesar暗号同様の頻度分析や推測により解析ができる。
また、Friedmanテストという、周期性に頼らず頻度のみから鍵長を推測する手法もあるようだ。

`oldcrypto.py`では、`tr`として表が与えられ、加えて各文字は`i ** 7`だけずらされている。
`i ** 7`を引き戻すことでずらしは除去できるので、同様な方法で解読ができる。

## implementation

``` python
#!/usr/bin/env python3
import functools
import math
import sys
import logging
logging.basicConfig(stream=sys.stderr, level=logging.INFO)
log = logging.getLogger()

with open('ciphertext') as fh:
    ciphertext = fh.read()
log.info('ciphertext: %s', ciphertext)

s = ''
for i in range(len(ciphertext)):
    c = ord(ciphertext[i]) - ord('a')
    s += chr((c - i**7) % 26 + ord('a'))
log.info('unshift: %s', s)

# Kasiski test
l = 6
dists = []
for i in range(len(s) - l):
    word = s[i : i+l]
    j = s[i + l : ].find(word)
    if j != -1:
        dists += [(i+l+j) - i]
log.info('dists: %s', str(dists))
dist = functools.reduce(math.gcd, dists)
log.info('dist: %d', dist)
assert dist == 20

freqs = [[0] * 26 for _ in range(dist)]
for i, c in enumerate(s):
    freqs[i % dist][ord(c) - ord('a')] += 1
# https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_the_first_letters_of_a_word_in_the_English_language
general_frequency = {
        'e': 0.12702,
        't': 0.09056,
        'a': 0.08167,
        'o': 0.07507,
        'i': 0.06966,
        'n': 0.06749,
        's': 0.06327,
        'h': 0.06094,
        'r': 0.05987,
        'd': 0.04253,
        'l': 0.04025,
        'c': 0.02782,
        'u': 0.02758,
        'm': 0.02406,
        'w': 0.02361,
        'f': 0.02228,
        'g': 0.02015,
        'y': 0.01974,
        'p': 0.01929,
        'b': 0.01492,
        'v': 0.00978,
        'k': 0.00772,
        'j': 0.00153,
        'x': 0.00150,
        'q': 0.00095,
        'z': 0.00074,
        }

tr = [
        [12, 9, 16, 3, 13, 15, 22, 17, 20, 1, 10, 24, 0, 4, 19, 5, 2, 7, 23, 14, 8, 21, 6, 18, 11, 25],
        [19, 16, 7, 5, 22, 3, 15, 2, 8, 14, 18, 17, 25, 13, 9, 6, 1, 11, 10, 0, 21, 20, 4, 23, 24, 12],
        [0, 7, 9, 14, 19, 8, 12, 1, 5, 2, 24, 11, 6, 21, 3, 15, 18, 25, 16, 4, 20, 13, 23, 22, 10, 17],
        [4, 15, 22, 13, 0, 10, 21, 14, 11, 19, 5, 8, 17, 3, 7, 1, 20, 12, 24, 9, 16, 6, 2, 25, 18, 23],
        [10, 23, 15, 25, 8, 16, 20, 21, 4, 11, 0, 9, 13, 12, 17, 2, 5, 14, 22, 24, 6, 7, 18, 1, 19, 3],
        [8, 10, 23, 7, 12, 6, 5, 3, 0, 18, 1, 14, 4, 22, 11, 21, 19, 20, 9, 16, 17, 15, 13, 2, 25, 24],
        [13, 19, 11, 15, 16, 22, 18, 23, 12, 24, 20, 2, 8, 0, 25, 3, 4, 21, 6, 1, 10, 17, 5, 7, 9, 14],
        [14, 2, 1, 24, 11, 23, 16, 20, 13, 10, 9, 4, 22, 8, 0, 25, 6, 19, 21, 17, 7, 18, 12, 5, 3, 15],
        [7, 4, 10, 21, 1, 20, 13, 0, 15, 12, 2, 18, 9, 6, 23, 8, 22, 24, 11, 25, 5, 3, 16, 14, 17, 19],
        [20, 1, 5, 16, 10, 2, 9, 19, 21, 6, 4, 25, 18, 24, 22, 23, 3, 17, 12, 7, 0, 8, 14, 15, 13, 11],
        [6, 13, 3, 2, 5, 4, 0, 9, 23, 7, 25, 21, 20, 1, 24, 18, 17, 16, 15, 19, 12, 11, 22, 8, 14, 10],
        [17, 6, 13, 23, 18, 19, 1, 16, 24, 25, 12, 15, 10, 2, 20, 11, 7, 0, 4, 5, 14, 22, 21, 3, 8, 9],
        [3, 22, 8, 0, 7, 21, 11, 4, 2, 16, 19, 6, 15, 25, 14, 12, 9, 23, 18, 10, 24, 5, 1, 17, 20, 13],
        [18, 3, 2, 1, 17, 12, 10, 24, 16, 9, 6, 19, 5, 23, 21, 22, 8, 4, 0, 11, 25, 14, 15, 13, 7, 20],
        [16, 24, 21, 12, 15, 14, 23, 18, 25, 20, 11, 10, 3, 17, 5, 4, 0, 13, 7, 22, 9, 2, 19, 6, 1, 8],
        [5, 17, 4, 19, 2, 0, 25, 22, 18, 23, 13, 16, 14, 10, 12, 20, 11, 1, 8, 3, 15, 24, 7, 9, 21, 6],
        [11, 8, 20, 22, 14, 7, 6, 5, 1, 21, 16, 0, 12, 19, 4, 17, 10, 15, 25, 13, 2, 9, 3, 24, 23, 18],
        [9, 21, 14, 17, 24, 5, 7, 6, 10, 0, 8, 23, 19, 15, 2, 13, 16, 3, 20, 12, 18, 1, 25, 11, 4, 22],
        [22, 5, 6, 20, 23, 1, 2, 25, 9, 8, 17, 13, 16, 11, 18, 24, 12, 10, 14, 21, 3, 19, 0, 4, 15, 7],
        [25, 18, 19, 8, 20, 17, 14, 12, 3, 13, 15, 22, 7, 9, 6, 10, 24, 5, 1, 2, 4, 23, 11, 21, 16, 0],
        [24, 20, 17, 9, 25, 13, 8, 11, 6, 3, 22, 7, 23, 5, 15, 14, 21, 2, 19, 18, 1, 16, 10, 12, 0, 4],
        [15, 25, 18, 10, 6, 9, 4, 13, 17, 5, 3, 20, 21, 7, 16, 0, 14, 8, 2, 23, 11, 12, 24, 19, 22, 1],
        [23, 14, 24, 18, 4, 25, 17, 7, 19, 22, 21, 12, 11, 20, 1, 16, 15, 6, 3, 8, 13, 10, 9, 0, 2, 5],
        [21, 11, 25, 6, 9, 18, 3, 10, 14, 4, 7, 1, 24, 16, 8, 19, 13, 22, 5, 15, 23, 0, 17, 20, 12, 2],
        [2, 12, 0, 4, 3, 11, 24, 15, 22, 17, 14, 5, 1, 18, 10, 7, 23, 9, 13, 20, 19, 25, 8, 16, 6, 21],
        [1, 0, 12, 11, 21, 24, 19, 8, 7, 15, 23, 3, 2, 14, 13, 9, 25, 18, 17, 6, 22, 4, 20, 10, 5, 16]
    ]

fkey = 'eeeeeeeeeeeeeeeeeeee'
fkey = '????????????????eeee' # CRYP
fkey = 't???????????????eeee' # crypT
fkey = 'tte?????????????eeee' # betweEN
fkey = 'tte????????????teeee' # Kasiski
fkey = 'tteet??????????teeee' # ciphER
fkey = 'tteet???????eieteeee' # SUBstitution
fkey = 'tteet??seeeteieteeee' # SUBSTitution
fkey = 'tteetseseeeteieteeee' # cryPTanalysis
assert len(fkey) == dist
key = ''
for i in range(dist):
    if fkey[i] == '?':
        key += '?'
        continue
    p = freqs[i].index(max(freqs[i]))
    for k in range(26):
        if tr[k][p] == ord(fkey[i]) - ord('a'):
            key += chr(k + ord('a'))
            break
log.info('key: %s', key)

def decrypt(ciphertext, key):
    plaintext = ""
    for i in range(len(ciphertext)):
        if fkey[i % len(fkey)] == '?':
            plaintext += '?'
            continue
        c = ord(ciphertext[i]) - ord('a')
        k = ord(key[i % len(key)]) - ord('a')
        p = tr[k][(c - i**7) % 26]
        plaintext += chr(p + ord('a'))
    return plaintext
log.info('plaintext: %s', decrypt(ciphertext, key))

assert key == 'classicalcipherisfun'
```

plaintext:

```
incryptanalysiskasiskiexaminationisamethodofattackingpolyalphabeticsubstitutioncipherssuchasthevigenerecipherinpolyalphabeticsubstitutioncipherswherethesubstitutionalphabetsarechosenbytheuseofakeywordthekasiskiexaminationallowsacryptanalysttodeducethelengthofthekeywordusedinthepolyalphabeticsubstitutioncipheroncethelengthofthekeywordisdiscoveredthecryptanalystlinesuptheciphertextinncolumnswherenisthelengthofthekeywordtheneachcolumncanbetreatedastheciphertextofamonoalphabeticsubstitutioncipherassucheachcolumncanbeattackedwithfrequencyanalysisthekasiskiexaminationinvolveslookingforstringsofcharactersthatarerepeatedintheciphertextthestringsshouldbethreecharacterslongormorefortheexaminationtobesuccessfulthenthedistancesbetweenconsecutiveoccurrencesofthestringsarelikelytobemultiplesofthelengthofthekeywordthusfindingmorerepeatedstringsnarrowsdownthepossiblelengthsofthekeywordsincewecantakethegreatestcommondivisorofallthedistancesthereasonthistestworksisthatifarepeatedstringoccursintheplaintextandthedistancebetweencorrespondingcharactersisamultipleofthekeywordlengththekeywordletterswilllineupinthesamewaywithbothoccurrencesofthestringthedifficultyofusingthekasiskiexaminationliesinfindingrepeatedstringsthisisaveryhardtasktoperformmanuallybutcomputerscanmakeitmucheasierhowevercareisstillrequiredsincesomerepeatedstringsmayjustbecoincidencesothatsomeoftherepeatdistancesaremisleadingthecryptanalysthastoruleoutthecoincidencestofindthecorrectlengththenofcoursethemonoalphabeticciphertextsthatresultmustbecryptanalyzedoooooooooooooooooooopsflagisthekeywithoopsprefixandbraces
```

---

# 0CTF 2015 Quals CTF: oldcrypto

-   2016年  9月  5日 月曜日 00:31:59 JST
    -   類問を解くのにいい感じの平文があるといいかもと思ったので追記とか修正とか
