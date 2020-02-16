---
layout: post
redirect_from:
  - /blog/2016/05/27/anagol-midi-note-number-to-frequency/
date: 2016-05-27T13:22:01+09:00
tags: [ "golf", "writeup", "anagol", "float" ]
"target_url": [ "http://golf.shinh.org/p.rb?MIDI+note+number+to+frequency" ]
---

# Anarch Golf 953. MIDI note number to frequency

## perl

37byteだった。私の提出はどれも`8.1758`に括り出すのをしていないので1B損している。

### 36byte

-   <http://golf.shinh.org/reveal.rb?MIDI+note+number+to+frequency/tails_1464078285&pl>

``` perl
printf'%.2f
',8.1758*2**($_/12)for<>
```

変換式 $f = 2^{\frac{d-69}{12}} \cdot 440$ そのままな素直なコード。

参考: <https://en.wikipedia.org/wiki/MIDI_Tuning_Standard>

## c

`exp2`を知らなかったので69byteを提出した。

### 65byte

-   <http://golf.shinh.org/reveal.rb?MIDI+note+number+to+frequency/mitchs_1464223499&c>

``` c
main(n){while(gets(&n))printf("%.2f\n",8.1758*exp2(atoi()/12.));}
```

環境依存な解。
入力文字列を`gets(&n)`でstackにだばあして、stackに残った`&n`を暗黙に`atoi()`に拾わせている。

### 67byte

``` c
main(n){while(~scanf("%d",&n))printf("%.2f\n",8.1758*exp2(n/12.));}
```

portableな解ならおそらくこれ。
`exp2`を知らないと1B損する。

## ruby

私は45byte。共通部分で抜けがあるので全部の言語で1Bずつ損していてつらい。

### 44byte

-   <http://golf.shinh.org/reveal.rb?MIDI+note+number+to+frequency/xsot_1464067441&rb2>

``` ruby
#!ruby -n
puts'%.2f'%2**($_.to_f/12+3.03136)
```

rubyでも素直にやる。幅があって、`8.1758`や`$<.map{|s|   }`でも同じ長さになる。

## python 3.x

### 50byte

-   <http://golf.shinh.org/reveal.rb?MIDI+note+number+to+frequency/mitchs_1464094702&py3>

``` python
while 1:print('%.2f'%2**(int(input())/12+3.03136))
```

皆これ。`**`は`%`より結合が強いけれど`*`はそうではないので、`'%.2f'%8.1758*2**(int(input())/12)`とはできない。
