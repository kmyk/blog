---
layout: post
alias: "/blog/2018/04/02/hackerrank-april-fool-contest-2018/"
title: "HackerRank April Fool Contest 2018"
date: "2018-04-02T00:46:02+09:00"
tags: [ "competitive", "writeup", "ctf", "guessing", "lojban" ]
---

writer: japlj, snuke, tozangezan の実質CTFわくわくコンテスト

<https://www.hackerrank.com/april-fool-contest-2018>

意外にもeditorial付いてたのでそっち読めばいいと思います。
解いてるときのメモなので以下はeditorial読まずに書いてます。

## 恒例行事

`Max Score: -10` なので触るな危険。
部分点で$-20$と$+10$みたいになってる可能性があるよなと思って確認のため `exit 1` みたいなのをRE狙いで投げたのにAC喰らってしまった: <https://www.hackerrank.com/contests/april-fool-contest-2018/challenges/ikigomi/submissions/code/1306855172>

## April Fool Quest 2018

わくわくCTFよりむしろオンサイト付きのまともなCTFで見る気がする

特別賞一覧にある以外にもいくつかある。
たとえば: すいかを踏む

## April Fool Spreadsheet 2018

わくわくCTF典型その1 spreadsheetからのforensic

とりあえずzipで落として`grep -o 'flag_\w\+'`とかするといくらか出てくる。他は面倒なので知らず

## おみくじ

提出ごとに$[0, 100]$でランダムに点数が貰える。無限回提出すると$100$点。
私の提出scriptはHackerRank対応まだなので手動でやって放置。$89.67$点。

負の点数が出てくることがないので複垢が不要。
去年のApril Fools' GTFのおみくじより良心的。

## 呪いの音声ファイル

わくわくCTF典型その2 聞きとりにくい音声ファイルを頑張って聞くだけ

面倒だししません

## Don't look, but feel

>   画像をみればわかる通り、答えは4です。

これ好き (解いてない)

## Black Stripes

`夏ですね (^_^;)` ってなにかなと思って提出すると `docchi muiterun` `motto hidari!` などと言われる。つまりすいか割り。黒い縞模様の果実。
$x = 10 \; y = 90$のあたりにある。

## Blue Panther

幾何つらい撤退

## Split String

HTML解析して [enviroment](https://www.hackerrank.com/environment)を見ると`Beautiful Soup@4.5.3`とあるのでこれを叩けばよさそう

普通にやったらサンプルは合ったのに落ちる。

>   適当です。そんなに長いのはないです。あんまり病的な例とかも入ってなくておおむね良心的だと思ってください。日本語とかも入ってないので安心してください。

本当か？

``` python
#!/usr/bin/env python3
import bs4
import sys
def go(soup, directory):
    directory = list(directory) + [ soup.name ]
    for tag in soup.contents:
        if isinstance(tag, bs4.Comment):
            pass
        elif isinstance(tag, str):
            for word in tag.split():
                print(' > '.join(directory[1 :]) + ':', word)
        else:
            go(tag, directory)
go(bs4.BeautifulSoup(sys.stdin.read()), [])
```

## THE EMPTY 4

提出すると `Want a hint? Look at the contest top page.` わくわくCTFにありがち。 でも分からない <https://www.hackerrank.com/april-fool-contest-2018> じゃないの

## THE EMPTY 5

なにもてがかりなし

## THE EMPTY 6

`my blue bird bring will the answer` とは
すぬけさんの表示名が化けてるがこれか？

## THE EMPTY 7

なにもてがかりなし

## THE EMPTY 8

[Disscussions](https://www.hackerrank.com/contests/april-fool-contest-2018/challenges/the-empty-8/forum)

## 太いHackerRank

``` python
#!/usr/bin/env python3
print('=' * 79)
print(''' _   _            _             ____             _    ''')
print('''| | | | __ _  ___| | _____ _ __|  _ \ __ _ _ __ | | __''')
print('''| |_| |/ _` |/ __| |/ / _ \ '__| |_) / _` | '_ \| |/ /''')
print('''|  _  | (_| | (__|   <  __/ |  |  _ < (_| | | | |   < ''')
print('''|_| |_|\__,_|\___|_|\_\___|_|  |_| \_\__,_|_| |_|_|\_\\''')
print('=' * 79)
```

だいたいこういうことだと思うのだがWA。bannerでもfigletでもない

## 太くないHackerRank

```
HackerRank
```

## Stop Watch

`sleep 2` でいいかと思いきやそうではない。
(TLE判定は別として)経過時間がCPU時間で測られるため。`alarm`を設置してからbusy loopしよう。

``` c++
#include <cstdlib>
#include <signal.h>
#include <unistd.h>
void handler(int sig) {
    exit(EXIT_SUCCESS);
}
int main() {
    alarm(2);
    signal(SIGALRM, handler);
    while (true);
}
```

## Welcome to ROC

やってない

## Wolf Sum

やるだけ。ただし「1000000007で*割ったもの*を答えてください」

## Programming in Python

C++/Python polyglot書くだけ

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
#define help using namespace std; int main() { int n; cin >> n; vector<int> a(n); REP (i, n) cin >> a[i]; REP_R (i, n) cout << a[i] << ' '; cout << endl; return 0; }
help
#if 0
input()
print(*reversed(input().split()))
#endif
```

## Dial Lock

ダイヤル錠。$\forall i. \; a\_i - n \equiv 0 \pmod{c\_i}$ならAC。
周期$c\_i$が互いに素なので中国人剰余定理が使える。

``` python
#!/usr/bin/env python3
import itertools
def chinese_remainder_theorem(eqn):
    import gmpy2
    '''
        eqn = [ (y_0, n_0), ... ] where
            x = y_i mod n_i
    '''
    x = 0
    m = 1
    for y, n in eqn:
        d = gmpy2.gcd(m, n)
        x += (m // d) * (y - x) * gmpy2.invert(m // d, n // d)
        m = gmpy2.lcm(m, n)
    return x % m

ato_at = {}
ato_at[ 0] = list(map(int, '1 2 4  1 4  1   8 18  6  17  0 32  13 32  9'.split()))
ato_at[ 1] = list(map(int, '0 1 3  0 3  0   7 17  5  16 30 31  12 31  8'.split()))
ato_at[ 2] = list(map(int, '1 0 2  6 2 12   6 16  4  15 29 30  11 30  7'.split()))
ato_at[10] = list(map(int, '1 1 4  5 5  4  15  8 19   7 21 22   3 22 46'.split()))
ato_at[19] = list(map(int, '0 1 0  3 7  8   6 18 10  27 12 13  35 13 37'.split()))
ato_at[33] = list(map(int, '0 2 1  3 4  7   9  4 19  13 29 36  21 42 23'.split()))
ato_at[2354436171179] = list(map(int, '0 0 0  0 0  0   0  0  0   0  0  0  22 19 17'.split()))

cycle = [ None ] * 15
for i in range(15):
    for m in itertools.count(1):
        for t in ato_at.keys():
            if (ato_at[0][i] - t) % m != ato_at[t][i]:
                break
        else:
            cycle[i] = m
            break

eqn = [ (ato_at[0][i], cycle[i]) for i in range(15) ]
n = 1145148108931919  # chinese_remainder_theorem(eqn)
for i in range(15):
    assert (ato_at[0][i] - n) % cycle[i] == 0
print(n)
```

## Dial Locks

Dial Locksと同様だが周期$c\_i$が互いに素でなく、中国人剰余定理が使えず解なし。ケース数が少ないので乱択。

``` python
import random
print(random.choice([ 2, 7 ]))
```

## Stalking

reconきらい。ExifではないっぽいしGoogle Street Viewで頑張る感じに見える

## Shiritori 2018

$8$番目気になる

``` python
print('ukai ? ? gyouza ? ? kaisyaku ? sinnkai ireko komoriuta tannka'.split()[int(input())-1])
```

## lo pilji .e lo sumji

問題文がlojbanなので読みます。以前すこし勉強したのにかなり忘れてしまっていた。

### 題

まず `lo pilji .e lo sumji` について。

`lo broda ku` で 「broda(x) を満たすような項 x」を意味する。
つまり Hilbertの$\epsilon$-symbol。
`ku` は閉括弧なので省略可能。
よって `lo pilji`, `lo sumji` はそれぞれ product, sum を意味する項。

[.e](http://vlasisku.lojban.org/e) は意味に関する積。
全体では「積でありかつ和」となる。

### 1段落目

1段落目は `ni'o .ui fi'i lo vitke be la'o gy. April Fool Contest 2018 gy. mi'a gleki .ijanai do pukfri lo nu namkei` 。

文章なのでまず構造がある。
[ni'o](http://vlasisku.lojban.org/ni%27o) は段落境界。HTMLにおける`<p>`。
[.i] は文境界。HTMLにおける`<br>`。新しい文を始めることを示す語のため、`.ijanai`のように空白を伴わず前置されることがある。
ちなみに `'` は h の音であり、 `.` は小休止。

1文目 `.ui fi'i lo vitke be la'o gy. April Fool Contest 2018 gy. mi'a gleki` 。
[.ui](http://vlasisku.lojban.org/ui) は幸福感を表わす心態詞。勝手な位置に挿入してよい。
[fi'i](http://vlasisku.lojban.org/fi%27i) は歓迎を表わす挨拶であり、挨拶の対象を引数としてとる。
[be] は部分適用。`broda be ko'a` のようにして broda の第2引数に ko'a を埋める。
[la'o](http://vlasisku.lojban.org/la%27o)はlojbanの言語でない文字列で表される項を指示するための冠詞。
sedで`s!foo!bar!`とやるようにdelimiter `!`を伴なってquoteを行なう。quoteしないとsyntax errorになるため。
今回のdelimiterは`gy`であり、`la'o gy .April. .Fool. .Contest. .2018. gy`までで「April Fool Contest 2018」を意味する。

2文目 `.ijanai do pukfri lo nu namkei` 。
`.ijanai` は文と文を繋ぐ接続詞。
抽象詞`nu`は命題$\phi$に前置して「$x_1$は命題$\phi$に表されるようなできごと」という述語を作る。

全体では「:smile: やあApril Fool Contest 2018の参加者、私は嬉しいよ、もしあなたが問題を解くことを楽しんでくれるなら」ぐらいか。

### 2段落目

1文目 `ni'o .e'o ko sampla fi lo nu namkei la'e di'e`。
`.e'o` は要求を意味する心態詞で、`ko sampla ...`と併せて「プログラム書いて」。
`fi`は引数位置を3番目に指定。`sampla`は「$x_1$は$x_3$を処理するプログラム$x_2$を書く」であり、$x_3$を埋めたいため。
`la'e`は「次で指示されるもの」であり、`di'e`は「直後の発話」を表す。
つまり「次で説明されるプログラムを書け」。

2文目 `.i li .abu .e li by. nacmei li ny`。
`li`は数式に対する冠詞。`.abu` `by` `cy` `ny` はそれぞれ文字$a, b, c, n`を表す。
文法上`ay`がだめなので後置のquote `bu`を使っている。
「$a, b$は長さ$n$の数列である」。

3文目 `. i do zbasu li cy. no'u lo nacmei be li ny`。
`no'u`は非制限の同格関係詞。`ko'a no'u ko'e` で項「ko'a (ko'e と同一でもある)」ぐらい。
「あなたは$c$ (長さ$n$の数列) を構成してください」。

4文目 `. i li cy.boixi.ibu pilji li .abuboixi.ibu li by.boixi.ibu gi'a sumji li .abuboixi.ibu li by.boixi.ibu`

先頭部分は`.i li cy boi xi .ibu pilji li .abu boi xi .ibu li by boi xi .ibu ...`とtokenizeされる。
`boi`は数式中の文字区切り。$s \cdot i \cdot n$と$\sin$のような区別のために要求される。`xi`はsubscriptを表す語。
よって「$c\_i$は$a\_i$と$b\_i$の積あるいは$a\_i$と$b\_i$の和である」。

5文目 `.i li xo nacyzmarai lo simsumji be li cy`
`xo`は質問の数量詞で、日本語でいうと「どんな数」、英語で言うと"what number"だが文頭への移動は発生せず普通に項として使える。
「$c$の総和としてありえるような値の最大値は何ですか」。
意味解析時に型error出そう 分からん

6文目 `. i ta'o lu lo tcidu bau lo lojbo li'u danfu be la .ku'eston. jufpau`
`lu`は`li'u`まで引用で、中身はlojbanの文法に合致する文字列。
`la`は`lo`と同様に使って「$\dots$と呼ばれているもの」。
よく分からないが「ところで「lojbanで読む人」は「"question"という語句」への答えである」とかか。

### 3段落目

`ni'o .e'i lo se sampla be do cu pruce fi lo namcu poi ke'a veldilcu le danfu be la'e di'u li ki'o xa ki'o zeciso`

`se`は引数位置の置換で、特に1番目と2番目を入れ換えるもの。
`cu`は括弧をすべていい感じに閉じるmarker。`lo`が(たいていは省略されるが)文法上要求する`ku`とかをいい感じにする。
`ki'o`は1000(kilo)であり日本語の「千」みたいな使い方をする数字の区切りで、`li ki'o xa ki'o zeciso`は百万六千七百三十九。
「あなたが書くプログラムはこの答えを$1,006,739$で割ったものであるような数を出力する」。

### 4段落目

`ni'o la'o .url. https://lojban.github.io/ilmentufa/glosser/glosser.htm .url. e la'o .url. http://vlasisku.lojban.org/ .url. selpli`

`.url.`はURLの引用。「<https://lojban.github.io/ilmentufa/glosser/glosser.htm>と<http://vlasisku.lojban.org/>が便利」。
でもこれだけだとつらいので<http://seesaawiki.jp/hajiloji/>と<https://ja.wikibooks.org/wiki/%E3%83%AD%E3%82%B8%E3%83%90%E3%83%B3>も使おう。

### input format

`ny. .abuboixipa by.boixipa .abuboixire by.boixire ra'ei .abuboixiny. by.boixiny.`

$y a\_1 b\_1 a\_2 b\_2 \dots a\_n b\_n$
