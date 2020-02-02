---
layout: post
alias: "/blog/2015/10/03/coderunner-2015-quala/"
title: "CODE RUNNER 2015 予選A 線分ゲーム「No Cross」 反省会"
date: 2015-10-03T23:27:34+09:00
tags: [ "coderunner", "competitive", "writeup" ]
---

暫定13位でテンション上がってたら、最終的に70位台。去年の本戦からまったく成長していない。

<!-- more -->

## [線分ゲーム「No Cross」](https://coderunner.jp/problem-pa.html)

### 過程

開始後とりあえず単一の線分の長さを取得するものを実装。
それを裏で回しながら、1本ずつ追加していく解法を実装。

これで順位が伸びるも、しばらくすると伸び悩み、困り果てる。
打開策として、既知の線分を長さ順にソートしてよいものから貪欲に取ることを試した。

しかし動くのが遅かったため、時間がないことに焦って、それで得られていた解を元に、1本ずつ追加するが一定以上長いやつだけ試す方針に変更した。
ランキング見たら80位とかになってて焦り、長さの制限を外し、さらにそれでいいのか不安になり、結局愚直解を回すのに戻った。
やるなら最後までやるべきだったし、そうでないなら最初からやらないべきだった。

### 反省点

-   考察が足りない
-   焦りすぎ

最初1時間は何があってもeditor触らない & 最後までランキング閲覧は封印、とかした方がかえって成績良くなりそう。

### 最終結果

```
0,560,103,475,107,677,110,948,117,20,119,528,126,206,130,944,133,340,137,347,140,733,143,204,148,683,149,193,152,236,157,854,162,963,167,30,169,611,17,329,170,936,172,875,18,264,184,428,185,792,187,80,196,758,199,699,218,831,219,279,22,423,224,374,227,949,233,510,235,429,238,313,24,786,241,921,246,649,248,482,249,330,250,618,251,266,253,272,254,795,255,373,261,442,262,605,269,398,277,505,28,304,280,899,287,348,288,641,294,760,296,462,297,853,305,981,309,527,314,810,322,929,341,706,345,631,350,61,353,400,362,543,366,732,370,380,371,69,38,907,387,975,389,41,401,485,405,414,406,826,407,715,411,471,412,892,425,636,434,990,438,564,445,777,456,816,461,519,463,776,466,593,467,477,468,820,472,857,473,638,481,731,49,838,492,694,504,75,508,743,522,737,526,599,529,765,545,704,551,87,557,83,561,72,563,884,575,702,584,719,598,992,601,988,603,805,621,909,623,851,627,830,646,978,65,779,663,923,67,735,68,807,690,995,691,749,698,902,703,943,707,88,73,925,76,920,783,856,796,979,803,845,808,92,825,956,843,859,850,934,855,950,862,94,871,915,895,935,904,972,984,993
```

`136`本 `5882`点

![](a.svg)

ひたすら愚直に回したもの

### 長さ順ソート

```
109,209,120,337,126,428,133,449,140,243,153,241,161,753,162,632,212,310,213,26,219,564,223,826,235,448,236,933,239,456,240,869,252,758,257,840,27,414,302,553,326,924,35,703,357,554,359,625,4,535,422,929,424,671,469,944,482,791,507,801,53,533,560,627,562,565,59,910,591,818,650,890,676,953,677,798,679,895,695,951,704,722,741,967,749,98,769,788,786,805,8,93,852,978,855,972,871,94
```

`49`本 `4333`点

![](b.svg)

よさげに見える。特に短い線分は後から追加したものなので、方針を崩さなければもう少し伸びていたはず

### 実装

``` python
#!/usr/bin/env python3
from common import *

dic = get_dic()
if 1 < len(sys.argv):
    best = sys.argv[1]
else:
    best = get_best(dic)
best = normalize(best)
print(best)

dicfh = open('dic.tsv', 'a')
while True:
    vs = vertices(best)
    if False:
        while True:
            p = random_line_pair()
            while p[0] in vs or p[1] in vs:
                p = random_line_pair()
            scr = submitw('{},{}'.format(p[0], p[1]), dic, dicfh)
            if 40 < scr:
                k = normalize('{},{},{}'.format(best, p[0], p[1]))
                if k not in dic:
                    break
    else:
        k = add_line(best, dic)
    result = submitw(k, dic, dicfh)
    if dic[best] < result:
        best = k
    if result != 0:
        print(k)
    print(k, result, file=dicfh)
    dicfh.flush()
```

``` python
import urllib.request
import time
import os
import random
import json
import sys
import traceback

def query(url): #=> str or None
    # print(url)
    try:
        res = urllib.request.urlopen(url, timeout=1)
    except Exception:
        traceback.print_exc()
    else:
        return res.read().decode()

def wait(sec=1.0):
    time.sleep(sec)

def submit(k): #=> int
    url = 'https://game.coderunner.jp/query?token={}&v={}'.format(token, k)
    result = query(url)
    try:
        result = int(result)
    except:
        return None
    print(result)
    return result

def normalize(k):
    vs = k.split(',')
    ls = []
    i = 0
    while i < len(vs):
        u, v = sorted([vs[i], vs[i+1]])
        if u != v:
            ls.append((u, v))
        i += 2
    ls.sort()
    return ','.join(map(lambda l: '{},{}'.format(*l), ls))

def get_dic(): #=> dict
    dic = {}
    with open('dic.tsv') as fh:
        for l in fh.readlines():
            k, result = l.split()
            k = normalize(k)
            dic[k] = int(result)
    return dic

def get_best(dic): #=> string
    ranking = []
    for k in dic:
        ranking.append((dic[k], k))
    if len(ranking) > 0:
        ranking.sort(reverse=True)
        return ranking[0][1]
    return ''

def random_line_pair():
    u = -1
    v = -1
    while u == v:
        u = random.randint(0,999)
        v = random.randint(0,999)
    return list(sorted([u, v]))

def random_line():
    u, v = random_line_pair()
    return '{},{}'.format(u,v)

def add_line(base, dic):
    k = base
    while k == '' or k in dic:
        if k != '':
            k += ','
        k += random_line()
        k = normalize(k)
        if k in dic and dic[k] == 0:
            k = base
        vs = sorted(k.split(','))
        if len(vs) != len(set(vs)):
            k = base
    return k

def vertices(k):
    return list(sorted(map(int, k.split(','))))

def submitw(k, dic, fh, w=1.0):
    if k in dic:
        return dic[k]
    result = None
    while result is None:
        result = submit(k)
        wait(w)
    dic[k] = result
    print(k, result, file=fh)
    fh.flush()
    return result

with open('token') as fh:
    token = fh.read().rstrip()
```

点数が既知の線分列に線分を追加したクエリを送ると、点数の差分から線分単体の場合の点数が分かるが、この単純な事実すら考慮してない辺りからもあれな感じが見える。

### 参考

visualizeはすぬけさんのdataを使用した。座標特定すごいなあ、としか言えない。

<blockquote class="twitter-tweet" lang="en"><p lang="ja" dir="ltr">あ、頂点のデータです。ビジュアライズしたい方、どうぞ。 <a href="https://t.co/i2QsQLFLwo">https://t.co/i2QsQLFLwo</a></p>&mdash; けけす (@snuke_) <a href="https://twitter.com/snuke_/status/650316553901092865">October 3, 2015</a></blockquote>
<script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>
