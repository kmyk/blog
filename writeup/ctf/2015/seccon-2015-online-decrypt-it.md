---
layout: post
redirect_from:
  - /blog/2015/12/06/seccon-2015-online-decrypt-it/
date: 2015-12-06T20:32:54+09:00
tags: [ "ctf", "seccon", "writeup", "crypto" ]
---

# SECCON 2015 オンライン予選 Decrypt it

競技屋なら問題なく解ける問題。ただし罠がひとつある。

<!-- more -->

## [Crypto 300. Decrypt it](https://github.com/SECCON/SECCON2015_online_CTF/tree/master/Crypto/300_Decrypt%20it)

### 問題文

>   $ ./cryptooo SECCON{\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*\*}
>   Encrypted(44): waUqjjDGnYxVyvUOLN8HquEO0J5Dqkh/zr/3KXJCEnw=
>   
>   what's the key?
>   [cryptooo.zip](https://github.com/SECCON/SECCON2015_online_CTF/blob/master/Crypto/300_Decrypt%20it/cryptooo.zip)

flagと暗号化器があって、暗号化器と暗号化結果が与えられるので、元のflagを求める。

### 解法

指示されたzipを落として開くと、`cryptooo`というバイナリが出てくる。
これを動かしてみて簡単に調べてみると、以下のような性質が分かる。

1.  出力はbase64でencodeされている。decode結果はasciiではない
2.  入力の長さと出力の長さはほぼ比例している。なんらかの手順で入力を置き変えて出力している
3.  特に、base64 decode後の出力の長さは入力の長さと一致する
4.  入力の$i$文字目を変化させると、出力の$i$文字目以降が変化する

1番目の性質は、単にdecodeすればよい。
3,4番目の性質から、入力文字列の先頭から順に決定していけばよく、また、そうするしかない。
これをやる。

``` sh
$ for i in {0..255} ; do echo -n $i' ' ; ./cryptooo 'SECCON{Cry'$(perl -e "print chr $i")'AAAAAAAAAAAAAAAAAAAAA}' | cut -d' ' -f2 | base64 -d | hexdump -C | head -n 1 ; done
```

などとして、先頭から順に決定していく。

<del> 最終的に`SECCON{Cry_P\x0ato_Oo_Oo1Oo_oo_Oo_O}`という文字列が得られる。
ただし途中に改行文字が挟まっている。なんだか怪しいが、これを除いて提出すれば通る。 </del>

`SECCON{Cry_Pto_Oo_Oo1Oo_oo_Oo_O}`。
なんらかのミスで混入したが、改行文字はshellの時点で消えるので`./cryptooo`に渡されず影響がなく、残りの部分が求まったように見える。
そういえば、結果は`crypto`になりそうだよね、とか言いながら作業をしていた。
以下のようになった状態で実行して、実際に効いているのは後ろの`t`であるのに、`\x0a`が効いているのだと勘違いしたのかもしれない。

``` sh
$ ... ; ./cryptooo 'SECCON{Cry_P'$(perl -e "print chr $i")'toAAAAAAAAAAAAAAAAA}' | ...
```

### 余談

線形に決定できそうだなあと思いdijkstraで探索するプログラムを書いたら、`_`や<del>`\x0a`</del>を探索範囲に入れていなかったため、求まらなかった。
手動でやって、おかしいなあどうやっても改行文字が入るぞ、などと言いながら全部複合化してしまったため、書いただけで出番はなかった。
