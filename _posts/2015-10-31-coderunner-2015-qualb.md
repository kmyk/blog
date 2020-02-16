---
category: blog
layout: post
date: 2015-10-31T23:40:54+09:00
tags: [ "competitive", "coderunner" ]
---

# CODE RUNNER 2015 予選B 魔法の力を、ためて戦え！「Charge And Hit」

本戦行けるのかとても怪しい。最高1位、最終74位。

問題文読み落としてたのが試合終了後発覚。とてもつらい。

<!-- more -->

## [魔法の力を、ためて戦え！「Charge And Hit」](https://coderunner.jp/problem-pb.html)

### 開始直後数十分

問題文読んで反射で書いた適当なonelinerで1位が取れる。

``` sh
while true ; do curl 'http://game.coderunner.jp/enter?token='$TOKEN ; echo ; sleep $[3+$RANDOM%2+$RANDOM%3] ; done
```

### 次の数十分

問題を把握したのでとりあえず書いたようなscriptで1位が取れる。chokudaiさんに名前を呼んでもらえるので嬉しい。

``` python
#!/usr/bin/env python3
...
while True:
    info = query_info()
    if info is None:
        query_attack()
        wait(0.8)
    else:
        if info['hp'] < info['power']:
            query_attack()
            wait(0.8)
    wait(0.2)
```

### 残り

**駄目**

1位を取ったpython scriptの出力を調整する際に、vim scriptの不調とかが原因で手間取ってたら10位ぐらい降下。
だんだん周囲が強くなっていくので改良してたが上手くいかず、以降ずっと順位が下り続ける。


### 考えたこと

-   攻撃力が敵の体力を上まわる少し前に攻撃するようにする。
-   部屋内で1位が取れればよいので、敵hpの半分以上を削れるなら攻撃する。
-   敵hpが少なくて殆ど点にならないとき(`hp < 10,000,000`)は攻撃しないする。(誰か親切な人がとどめをさして)次に出てきた元気な敵を(たいてい一撃で)倒すようにする。
-   部屋は1分で閉じるので、残り$0.5$秒とかになったらとりあえず攻撃しておく。
-   体力の大きい元気な敵に、他人が攻撃する直前に、倒れないぎりぎりの攻撃をする、というのが理想。

頑張ったけど駄目でした。


### 誤読

部屋内の残りの敵の体力が取れることに気付いてなかった。

再発防止にはなにをどうすればいいのだろう。


---

# CODE RUNNER 2015 予選B 魔法の力を、ためて戦え！「Charge And Hit」

-   Tue Nov  3 00:26:27 JST 2015
    -   問題読み落としてたの発覚したので修正
