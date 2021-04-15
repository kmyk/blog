---
layout: post
redirect_from:
  - /writeup/golf/anarchy-golf/add5/
  - /blog/2018/03/05/anagol-add5/
date: "2018-03-05T11:50:51+09:00"
tags: [ "golf", "writeup", "anagol", "brainfuck" ]
"target_url": [ "http://golf.shinh.org/p.rb?add5" ]
---

# Anarchy Golf: 1038. add5

## brainfuck

$58$byte cheat で最短タイ。mitchsプロと並んだの嬉しすぎる (これは罠で問題が比較的単純だっただけ)。

``` brainfuck
$ xxd a.bf
00000000: 3c2b 5d2c 2c2c 5b2e 3c5d 2c3e 2c2b 5b2d  <+],,,[.<],>,+[-
00000010: 3c2e 3e3e 2c2b 5d3c 5b3c 5d3e 5b2e 3e5d  <.>>,+]<[<]>[.>]
00000020: 0028 7829 3a0a 2020 2020 7265 7475 726e  .(x):.    return
00000030: 2078 2b00 6464 6120 6665                  x+.dda fe
```

### 解説

整形すると以下。`\0`はnull文字

``` brainfuck
#!/usr/bin/env bfi
<+]
,,,[.<]
,>,+[-<.>>,+]
<[<]>[.>]
\0(x):
    return x+\0dda fe
```

順に、

-   `<+]` はbuffer overflow。`x+\0dda fe` の右にdata pointerを移動
    -   $60$byte/$62$byte付近なので、stack上の`int prog_len;`から`<`/`>`を借りれる/混入することに注意。今回始めて気付いた
-   `,,,[.<]` で `def add` まで出力。出力`def`の`d`を入力`add`の`d`から持ってくることで$2$byteぐらい削れる
-   `,>,+[-<.>>,+]` は入力の残り`99999999`などを読みつつ出力。改行文字を出力してはいけないので一歩後ろを出力していく
-   `<[<]>[.>]` は残り全部の出力。`99999999`を読むときに`return x+`の直後に繋げて配置することで`[.>]`が一度で済んでいくらか削れる
