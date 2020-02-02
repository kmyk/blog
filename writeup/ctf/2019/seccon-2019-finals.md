---
layout: post
title: "SECCON CTF 2019 Final"
date: "2019-12-23T23:59+09:00"
tags: [ "ctf", "writeup", "seccon" ]
---

SECCON CTF 2019 国内決勝にわたし個人のみからなるチーム kimiyuki として参加し、$2260$ 点を得て $2$ 位でした。

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">SECCON 国内決勝 2位でした。文部科学大臣賞もらいました。ありがとうございました <a href="https://t.co/QL2SvAal7H">pic.twitter.com/QL2SvAal7H</a></p>&mdash; うさぎ (@a3VtYQo) <a href="https://twitter.com/a3VtYQo/status/1208659189150543873?ref_src=twsrc%5Etfw">December 22, 2019</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

attack flags を合計 $10$ 個取り、defense points はおそらく問題 4 のみから $1260$ 点取りました。
ちゃんと面白い問題を解いたことが効いた結果の国内 $2$ 位だったのでよかったです。
あまり面白くない問題もいくつかありましたが、個人参加なので自分がやりたくない問題は無視できて快適でした。

以下は問題の解法の説明と感想です。

## 1. 注意力 port knocking

### 問題概要

チームごとにサーバーの port が指定される。
サーバーのバイナリが配布されている。
ただし次のような注意がある。

>   Caution: If your service process goes to wrong state, we will not restart till all team's score goes to no count or any trouble is found.

### 解法

接続をすると attack flag が得られます。
defense points は得ていません。

問題文の $1$ 行目まで読んでとりあえず `nc` で接続し、そのまま Ctrl-C を押してしまい詰みました。
続きを読むと注意書きがあり、`we will not restart` とあったので諦めました。
しばらくしたらなぜかサーバーが復活していたので attack flag は拾えました。
まじめにやるべき問題ではなさそうだったのでバイナリは読まずに雰囲気だけでスクリプトを書いて回していましたが、defense points は得られませんでした。

### 感想

あまり好きでないです。
なにをやらせたいのかよく分かりません。
一度でも攻撃に失敗すると詰む (相手にバレて対策を取られるなど) という状況は現実での攻撃でならありそうで、教育的な問題としての出題なのかもしれません。
しかしそのような理不尽要素を娯楽であるはずの競技にそのまま持ち込まれてもただ不快なだけです。


## 2. adversarial example ぽいやつ

### 問題概要

サーバーに png 画像を提出すると、何らかの画像認識をして認識率が返される。
認識率の十分に高い画像を提出すると attack flags がもらえる。
全参加者の中で認識率の最も高い画像を提出したチームは defense points がもらえる。

### 解法

attack flags の認識率の要求は低かったので適当に画像を作って山登り法で改善をすれば十分でした。
defense points は得ていません。

### 感想

パンダをテナガザルに変えるようなことをさせたいのかなあと感じる問題でした。
defense points を狙わなかったので細かい話は分かりません。
後から聞いた話では色を少しずつ変えつつ単色ベタ塗り画像を送るのが簡単かつ高認識率だったらしいです。
なぜ？

ただし defense points の計算がとってもバグっていたのは酷かったと思います。
$1$ 日目はこの問題の defense points がなぜかすべてわたしに付与されていたようで、何もしていないのに点数が上昇し続けていました。
これのおかげで $1$ 日目は $1$ 位を独走してしまいました。
もちろん $2$ 日目の朝にはすべて没収されており、$10$ 位ぐらい (このとき順位表の表示に別のバグもあり正確な順位は不明) に戻っていました。

おそらくこれで点数修正をした影響により、$2$ 日目の朝は順位表の表示がバグっていました。

ちなみに、謎の点数上昇が発生していることは確認していましたが、問題 2 の defense points の影響だということは $1$ 日目の終了後に知りました。点数が増える分には対応を急ぐ必要はないため放置していたことや、NIRVANA が映っている壁から遠い席だったのでどの defense points が入っているかの確認が手間だったことなどが理由です。

## 3. 謎アーキ

### 問題概要

なんだっけ

### 解法

解いていません。

### 感想

やりません。
環境構築が面倒なこと、よく分からないアーキテクチャを扱うことに特に魅力を感じないことが理由です。

## 4. PIN の trace を合わせるやつ

### 問題概要

バイナリと、そのバイナリにある隠された入力を食わせて得られた実行トレースが与えられる。
この実行トレースは Intel Pin を使って得られ、実行された分岐命令とその分岐先が時系列順に記録されている。
この隠された入力と同じ実行トレースを持つ入力を復元して提出すると attack flags や defense points が得られる。

バイナリや実行トレースは attack flags のための $4$ 種と defense points のための $12$ 種類存在する。

### 解法

貪欲法です。基本的には次をします:

1.  「文字列を受けとり、それを入力としてバイナリを実行し、その結果の実行トレースが目標のものと何番目まで一致しているかを返す」というオラクル $f(s)$ を Pin を使って書く
2.  文字列 $s$ を空文字列 $s = \epsilon$ から始めて、「$s$ の末尾に追加したときの実行トレースの一致量 $f(s + c)$ が最大となるような文字 $c$ を $s$ の末尾に付け加える」という操作を繰り返す

バイナリが逆ポーランド記法の電卓 (`box1` や defense points) および CPU エミュレータ (`box3`, `box4`) であり入力は線形に消費されることから、この貪欲法はかなり上手く行きます。
もちろんこれをまったくそのままやると「それを末尾に追加する時点では実行トレースに影響しないがしばらく後になって影響するような文字」によって失敗しますが、バイナリを読んで個別に対策を加えたり手で修正したりすればなんとかなります。

ただし `box2` は傾向が異なるので個別に解きます。と言っても実行トレースには入力の長さしか影響しないので簡単です。

### 実装

以下は defense points 用のコードです。

速度については `box1` に対し手元のノートパソコン上で $41$ 秒でした。
数値の二分探索やオラクル発行の並列化をすれば (バイナリを読んで得られる知識を使わずに) あと最低でも $10$ 倍は速くできます。
コードの仕様な入力の傾向 ($5678$ のような大きな数値が来ないなど) の知識を使えばいくらでも速くできるのは明らかでありつまらないので、いかにバイナリを読まずに誤魔化すかが腕の見せ所かなと思っています。

``` python
#!/usr/bin/env python3
import math
import requests
import time
import os
import json
import subprocess
import pathlib
import msgpack

base_url = "http://10.1.4.1/"

def submit_data(api, _input):
    ### NOTE: Please wait
    time.sleep(2)
    ### NOTE: Challenge server API use MsgPack
    print("\n[*] API {} with input = {}".format(api, _input))
    res = requests.post(base_url + api, data=msgpack.packb({'input': _input}))
    try:
        res_decoded = msgpack.unpackb(res.content)
        print(res_decoded)
        return res_decoded
    except Exception as f:
        print(res.content)

def download_latest():
    ### Recommend use curl or wget :)
    time.sleep(2)
    print("\n[*] Defense round file download")
    os.system("curl {}/defense/latest.zip > latest.zip".format(base_url))
    os.system("rm -rf latest")
    os.system("unzip -d latest latest.zip")

def get_current_round():
    rounds = list(pathlib.Path('latest').glob('Round *'))
    return max([int(path.name.split()[1]) for path in rounds])

PIN_ROOT = pathlib.Path('pin-3.11-97998-g7ecce2dac-gcc-linux')
binary = 'latest/box'
binary_trace = 'latest/box.trace'

def compare(xs, ys):
    for i, (x, y) in enumerate(zip(xs[4:], ys[4:])):
        if x['event'] == y['event'] == 'exit':
            return math.inf
        if x['event'] != y['event'] or x['inst_addr'][-2:] != y['inst_addr'][-2:] or x['branch_taken'] != y['branch_taken']:
            return i
    assert False

def branchtrace(formula):
    assert formula
    cmd = [str(PIN_ROOT / 'pin'), '-t', PIN_ROOT / 'source/tools/SimpleExamples/obj-intel64/branchtrace.so', '--', binary, formula]
    # print(cmd)
    subprocess.run(cmd)
    with open('branchtrace.out') as fh:
        return json.load(fh)

def list_next_formula(formula):
    for delta in [None, 'a', 'b', 'c', 'd', 'e', 'f']:
        if formula and formula[-1] is None and delta == 'd':
            yield formula[:-1] + [None, delta]
        else:
            yield formula + [delta]

def encode_formula(formula):
    s = ''
    for c in formula:
        if c is None:
            s += '0000'
        elif isinstance(c, int):
            s += '%04d' % c
        else:
            s += c
    return s

def evaluate(formula):
    if not formula:
        return -1
    with open(binary_trace) as fh:
        binary_trace_json = json.load(fh)
    i = compare(branchtrace(encode_formula(formula)), binary_trace_json)
    print('formula', formula, '->', i)
    return i

def solve(formula):
    cur = evaluate(formula)
    while not math.isinf(cur):
        best_formula = None
        best_nxt = cur
        for next_formula in list_next_formula(formula):
            nxt = evaluate(next_formula)
            if math.isinf(nxt):
                return next_formula
            if best_nxt < nxt:
                best_formula = next_formula
                best_nxt = nxt

        if best_formula is not None:
            formula = best_formula
            cur = best_nxt

        else:
            if None not in formula:
                break
            i = len(formula) - list(reversed(formula)).index(None) - 1  # rindex
            for value in range(50):
                formula[i] = value
                nxt = evaluate(formula)
                if cur <= nxt:
                    cur = nxt
                else:
                    formula[i] = value - 1
                    break
    return formula

# formula = [None, 0, 7, 'f', 0, 11, 'f', 'd', 'c']
# print(evaluate(formula))
# exit()

download_latest()
rnd = get_current_round()
cache_path = pathlib.Path('latest.cache/Round %d' % rnd)
formula = []
if cache_path.exists():
    with open(str(cache_path)) as fh:
        cache = fh.read().strip()
        formula.append(cache)
        print('read', repr(cache))
else:
    os.system('notify-send newround')
formula = solve(formula)
with open(str(cache_path), "w") as fh:
    print('write')
    fh.write(encode_formula(formula))
data = submit_data('/defense/latest/submit', encode_formula(formula))
if b'correct' not in data[b'message']:
    os.system('notify-send error')
```

### 感想

良い問題でした。
ちゃんと問題として成立しており、解いていて楽しかったです。

正答を提出しても defense keyword が書き込まれないというバグはつらかった (実際に解き終わって提出してみるまでバグがあることに気付く余地がない + defense points なのでバグ修正が遅れれば遅れるほど得られる点数が下がるので) ですが、他の問題を眺めて冷静になると許せます。
競技中は作問者にかなり文句を言ってしまった気がしていて、反省しています。
こちらで提出内容や提出時刻などの証拠を残していなかったので詫びフラグは難しいかなと思いましたが、競技中のパケットはすべて記録されているようで、その情報から復元をしてもらえました。
ところで「パケットはすべて記録されているので後で復元します。いまは defense keyword が書き込まれないけどとりあえず解法は送信し続けておいてください」のようなアナウンスがあればなおよかったと思います。

そういえばなぜわざわざ MessagePack だったのでしょうか？
単に JSON の方が分かりやすいはずです。
特に目的なく非標準的な要素を入れるとバグらせたときに問題切り分けのステップが増えるのでおすすめしません。

問題の使い回しらしいという噂もありました。
作問者に聞いてみると今年の SECCON の予選で出題した問題の拡張だったらしいです。
その年の予選の問題の拡張であれば、使い回しが良くないとされる理由である「前回の問題を知らない人が不当に不利になる」「何度も似た問題を出されてもつまらない」などの批判は回避されるので、基本的には大丈夫なのだと思います。
しかし、わたしは予選では pwn も rev もまったく解いていないのでその問題を知りません。かなしいね。

この問題以外のいくつかの問題もそうですが、去年までと違って defense keyword を自分で取得する必要がなかったのは楽でよかったです。
あと Ghidra がすごく便利でした。

## 5. snake game

### 問題概要

snake game の AI を書く。
これをサーバーとして公開しておくと運営側から接続が来て参加者同士で対戦が行われる。
一番強い AI を書いたチームに defense points が入る。

### 解法

強い AI を書けばよいです。
わたしはサンプル AI をそのまま公開して放置していました。

### 感想

問題として悪い点は特にないですが CTF でもセキュリティ関連でもなく、わざわざ SECCON でやりたいものではないなあと思って後回しにし、そのまま終了しました。
ところで、今回のように bot を書いて戦わせるコンテストが開催されているサイトとして [CodinGame](https://www.codingame.com/) というのがあり、どうせやるならこちらがおすすめです。
ヘビっぽい問題もあります ([URL](https://www.codingame.com/multiplayer/bot-programming/tron-battle))。

「他のチームが AI をどの IP のどの port で公開してるかが分かるので、まじめに AI を書いてる強いチームに運営のふりをして接続して代わりに戦わせる」という案は、試してみたところ接続が通りませんでした。
おそらく運営に対策されていたのだと思います。


## 6.1. mimura (Hardware)

### 問題概要

何らかのハードウェアが説明なしに渡される。

### 解法

解いていません。

### 感想

ファームウェアの吸出しなどが必要そうですが、この手のものは環境構築が面倒なので見なかったことにしました。

## 6.2. syzbot panic (Fuzzing)

### 問題概要

syzbot に関するクイズが 5 問ある。すべての答えを連結したものが flag となる。
クイズは (Q1) を除いてすべて「……の commit hash は何？」という形式である。

>   (Q5) What is SHA-1 (only first 10 characters, in lower hexadecimal format) of a commit that explains the following improvement?
>   Currently, syzbot might by error generate C reproducer programs using incorrect structure definition (e.g. "struct serial_struct"). Therefore, a utility to validate correctness of structure definition was added.

### 解法

解いていません。

### 感想

これはかなり嫌いです。
どのあたりに面白さや楽しさがあると思って出題したのか気になります。
クイズの話題はセキュリティぽいですが、解法はおそらくただ検索を頑張るだけぽいので flag を得るための手段にセキュリティ要素はないはずです。
CTF をまったく知らない人が突然「セキュリティに関する問題作って」と言われて嫌々でっち上げた問題なのではと疑っています。

問題ページの HTML がすこし壊れていたのがいい話ぽかったです。文中のソースコードの `<pre>` の中に `#include <stdio.h>` と書いて `<stdio.h>` というタグが出現してしまっていましたが、正しくは `#include &lt;stdio.h&gt;` とすべきです。

## 6.3. Factor the flag (Crypto)

### 問題概要

>   I hid the SECCON{} flag in a big prime number.
>
>   1401111111111111111111111111111111111111111111111111111111111111111111111111111
>   1111111111111111111111111111111111111111111111111111111112220791111111111111111
>   1111111111111111111111111111122207911223089031988903088023088023088920012001200
>   2319889030879222080230880230890319887911122318879211992120012999912120013000013
>   0000131008920012001199121200120022089200130000119912119911121200120011992119912
>   1199121199121199121200130101000012001199121200120930009200130000119921199111121
>   2001200119921199121199121199121199121200130010208012002318879112120929999112120
>   9299991212103188892001200119912230890318889199121199121200130000131007911112119
>   9212092091991211992119912120013010111188791222079112129999121199121199121200130
>   0001200119911121200120012091992119921299992120013010099991112119911112129999121
>   1991211991212001300001200120012001209199223198889199212001209199213010099991112
>   1199212001299991212001300001300001300001200120012001299991111212091991212001209
>   1992130100999911121199122308903198890308802308802308892001200119922308903198879
>   2121031988903088011992130100999911121199111111111111111111111111111111111111111
>   2220791111111111111111111111111111111111111111111112220791111111111111111111111
>   1111111111111111111111111111111111111111111111111111111111111111111111111239593

### 解法

与えられた数字を連結して <http://factordb.com> に投げて ([URL](http://factordb.com/index.php?query=1401111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111222079111111111111111111111111111111111111111111111222079112230890319889030880230880230889200120012002319889030879222080230880230890319887911122318879211992120012999912120013000013000013100892001200119912120012002208920013000011991211991112120012001199211991211991211991211991212001301010000120011991212001209300092001300001199211991111212001200119921199121199121199121199121200130010208012002318879112120929999112120929999121210318889200120011991223089031888919912119912120013000013100791111211992120920919912119921199121200130101111887912220791121299991211991211991212001300001200119911121200120012091992119921299992120013010099991112119911112129999121199121199121200130000120012001200120919922319888919921200120919921301009999111211992120012999912120013000013000013000012001200120012999911112120919912120012091992130100999911121199122308903198890308802308802308892001200119922308903198879212103198890308801199213010099991112119911111111111111111111111111111111111111122207911111111111111111111111111111111111111111111122207911111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111239593)) その素数を [fold(1)](https://linuxjm.osdn.jp/html/GNU_textutils/man1/fold.1.html) などで長方形にすると flag が見える。

### 感想

ジャンルが welcome とか misc だったなら面白くもないが批判されるほどではない問題だったと思いますが、ジャンルが crypto なのはすごく嫌な感じです。
どのあたりが crypto なのでしょうか？

### 6.4. Bad Mouse (Binary)

### 問題概要

USB デバイスが渡される。パソコンに刺すとマウスカーソルが動く。
ファームウェアは配布されている。

### 解法

解けていません。

### 感想

マウスカーソルがなにやら動いていたが、これが何を意味するのか分かりませんでした。
これが分からないとバイナリを読んでも無駄なので、モールス信号などと推測して [pynput](https://pypi.org/project/pynput/) とか [DIGImend/usbhid-dump](https://github.com/DIGImend/usbhid-dump) などを試していたがはずれでした。
正解は「MS ペイントなどを開いておくとその上に flag を描画してくれる」だったらしいです。
なんだか面白そうなのに、本質でない guessing 要素で詰まって手を付けられなかったのは残念だったなと思います。
複数人チームなら誰かひとりぐらいはペイントに気付くだろうし、悪い問題ではなさそう。

## 6.5. QR Decoder  (QR Rev Pwn)

### 問題概要

QR Code を含む画像を受けとって出力するだけのバイナリが渡され、それがサーバー上で動いている。
flag は $2$ 個ある。
バイナリには明らかな BOF がある。

### 解法

Ghidra に食わせると `if (strcmp(buf, "QR-Code:Hello, world!\n") == 0) { /* print flag1.html */ }` が見えるので `qrencode -o hello.png 'Hello, world!'` して投げると flag 1 が取れます。

flag 2 は解けませんでした。

### 感想

コンテスト中は良問ぽく見えていたので解きたいなと思って頑張っていましたが、結局最後まで flag 2 は分かりませんでした。
明らかな BOF があるので shell を取るのだと思っていたのですが、後から聞くと実は単にブラウザで <http://10.1.5.1:8182/cgi-bin/flag2.txt> を開けばよいそうです。
ジャンル名の `QR Rev Pwn` とは何ですか？


## リンク

-   <https://www.seccon.jp/2019/>
