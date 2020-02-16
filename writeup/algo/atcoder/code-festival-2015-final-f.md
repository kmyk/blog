---
layout: post
alias: "/blog/2015/11/26/code-festival-2015-final-f/"
date: 2015-11-26T23:03:08+09:00
tags: [ "competitive", "writeup", "codefestival", "graph", "cycle", "math", "eulerian-path" ]
---

# CODE FESTIVAL 2015 決勝 F - 歩くピアニスト

本番中に解けた。6完できたのは嬉しいけれど、5完最速だった状況から終了間際の滑り込みACをしたので、順位の点ではほぼ変動がなかった。

<!-- more -->

## [F - 歩くピアニスト](https://beta.atcoder.jp/contests/code-festival-2015-final-open/tasks/codefestival_2015_final_f) {#f}

### 問題

十分に広いピアノの鍵盤がある。
以下のような演奏は可能か答えよ。

-   `ド` `レ` `ミ` `ファ` `ソ` `ラ` `シ`の音をそれぞれ$C_i$回鳴らす。
-   ある音を鳴らした後は隣の音を鳴らす。
-   `ド`の音から始まって`ド`の音で終わる。

### 解説

[解説](http://www.slideshare.net/chokudai/code-festival-2015-final)ではグラフを用いて説明していて賢いなあと思うが、同じことを書いても仕方がないように思うので、本番私が用いた考え方を、考えた順に説明する。


まず考えるのは、始めの`ド`の音からいくつ音階の離れた`ド`で終わるかである。
対称性から、終わりの`ド`は始めの`ド`より高い`ド`としてよい。
次に、寄り道、を考える。
つまり、ある`ド`からひとつ上の`ド`へ登っていく過程で、いくつか昇ってまた同じところまで戻ってくる、という場合を考える。いくつか降りてからまた同じところまで戻ってくるのは向きが逆なだけと見てよい。戻ってこない場合とは、登っていく過程そのものである。
1回の寄り道は、戻り始めの音と、間の音たちと、折り返す音のそれぞれを$1, 2, 2, \dots, 2, 1$回鳴らす。

大きく昇る寄り道は、1音だけ昇る寄り道の和として表せる。鳴らした回数に関する式で書くと、$(1, 2, 2, \dots, 2, 1) = (1, 1, 0, 0, \dots, 0) + (0, 1, 1, 0, \dots, 0) + \dots + (0, 0, \dots, 0, 1, 1)$である。
また、終わりの`ド`の高さに関して、1音だけ戻る寄り道を7回行なうこと、あるいは始点と終点が同じである寄り道を考えれば、$(2, 2, 2, 2, 2, 2, 2)$という寄り道を構成でき、これは終わりの`ド`の音が2オクターブ高いという状況と同じである。このことから、終わりの`ド`は、始まりの`ド`と同じ高さか、1音階高い場合のみを考えればよい。

残るは、$(1, 1)$という1音の寄り道の和で、$c_i$を構成することを考えればよい。
ただし、隣から移動してきて鳴る音でないという点で面倒な最初の1音目の`ド`の分の$1$を$c_1$から引いておく。
`ド`の音にから始まる寄り道を$a_1$回したとすると、`レ`の音では寄り道は必ず$a_2 = c_2 - a_1$回必要で、以降`シ`の音まで寄り道の回数が定まり、`ド`の音の回数$c_1$において整合性があるか見ればよい。
$a_1$は、簡単に解くことで$c_i$の関数として計算できる。あとは、寄り道の回数が負のものがないこと、始まりと終わりの`ド`の高さが同じ場合、到達できない場所での寄り道が要求されていないことを確認すればよい。

`ド`を鳴らす回数が$0,1$の場合、到達できない音を鳴らす場合は別に処理する。

### 実装

本番の苦労が思い出される汚さだったので、ちょっと整理した。

``` python
#!/usr/bin/env python3
def all_connected(c, initials):
    usable = [False] * 7
    def f(i):
        if c[i]:
            usable[i] = True
            for j in [(i+1)%7, (i-1)%7]:
                if not usable[j]:
                    f(j)
    for it in initials:
        f(it)
    for i in range(7):
        if c[i] and not usable[i]:
            return False
    return True

def all_non_negative(c):
    return 0 <= min(c)

def bar(c, is_loop): # solve
    c = list(c) # new list
    b = c[0] - c[6] + c[5] - c[4] + c[3] - c[2] + c[1]
    if b < 0:
        return False
    if b % 2 != 0:
        return False
    a = b // 2
    c[0] -= a
    c[1] -= a
    for i in range(1,7):
        c[(i+1)%7] -= c[i]
    if not all_non_negative(c):
        return False
    if c[0] != 0:
        False
    c[0] = a
    if not is_loop and not all_connected(c, [0, 6]):
        return False
    return True

def foo(c): # drop trivial cases and prepare c
    assert len(c) == 7
    if c[0] == 0:
        return False
    if c[0] == 1 and sum(c) != 1:
        return False
    if not all_connected(c, [0]):
        return False
    c[0] -= 1
    if bar(c, False):
        return True
    c = [x-1 for x in c]
    if not all_non_negative(c):
        return False
    return bar(c, True)

if foo(list(map(int,input().split()))):
    print('YES')
else:
    print('NO')
```
