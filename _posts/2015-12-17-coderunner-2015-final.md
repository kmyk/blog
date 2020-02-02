---
category: blog
layout: post
title: "CODE RUNNER 2015 決勝"
date: 2015-12-17T21:03:16+09:00
tags: [ "competitive", "onsite", "coderunner" ]
---

7位を取りました。とても嬉しい。

![](/blog/2015/12/17/coderunner-2015-final/standings.png)

<!-- more -->

## 本戦前

課題やら試験やらが溜まっていて非常に厳しい状況の中、夜行バスに耐えて東京へ。
6時到着だったので、時間まで、適当な場所で場阿忍愚ctfをしたり、charlotte展を見たり、試験勉強をしたりした。

時間になって会場に行って受け付けをしていたら人に話しかけられた。
同じ大学ののコンピュータ部の先輩で、以前一度会っているとのこと。
すごい記憶力だなあと思った。julia言語を紹介されたので、brainfuckを紹介しておいた。

会場入口でredbullを配っていた。何故klabドリンクでないのかとても気になった。
懇親会で聞いたら生産が間に合わなかったのだとか。

暇だったので本番の問題のページのurlを推測して叩いてみたら、何故か200していて報告しに行ったりもした。
このおかげで本戦開始直後の混乱は回避できた。

ある人と「どちらかが優勝したら相手に焼き肉を奢る」という約束をした。
懇親会のときに聞いたら、焼き肉食べれるのではとかなり期待していた、とのことであった。

## 本戦 [会社経営ゲーム「Assign Task」](https://coderunner.jp/problem-final.html)

開始直後、適当にapiを叩いたら負の点数が入ってしまい驚く。
さすが本戦というだけある。

開始15分ぐらいで、以下のような簡単な貪欲機が完成。手動で動かしたり、`while true ; do ... ; done`に突っ込んだりして、とりあえず点数が入り初める。

``` python
info = query_getinfo()
task = query_taketask()
worker_ids = []
for worker in info['workers']:
    if worker['time'] == 0:
        if 5 < worker['speed'][task['id']]:
            worker_ids.append(worker['id'])
query_assign(task['id'], worker_ids)
```

開始30分ぐらいで、既に1位であった。

ランキングを見てたら点数が減っていて驚く。
問題文をよく見たら30分ごとに半減とあった。
この感じだとやはり後は順位下がる一方だなあ、という思いで問題文を読みなおしていた。

外注状況を見ても誰も何もしていなかったので、死に要素なのかなとか思っていたが、開始1時間後ぐらいには外注が見え初める。とりあえずそれらしいのを書く。

``` python
info = query_getinfo()
for worker in info['workers']:
    print(worker)
for task in info['tasks']:
    print(task)
for task in info['outsources']:
    print(task)
out = query_getout()

if len(info['tasks']) == 0 and len(info['outsources']) == 0:
    for task in out['outsources']:
        if task['reward'] < 100:
            continue
        print('try out', task['id'])
        print(task)
        for lim in [9,8,7]:
            worker_ids = []
            for worker in info['workers']:
                if worker['time'] == 0:
                    if lim <= worker['speed'][task['pattern']]:
                        worker_ids.append(worker['id'])
            if len(worker_ids) == 0:
                continue
            result = query_assign(task['id'], worker_ids)
            if result is not None:
                sys.exit(0)
            else:
                wait(0.05)

workable = 0
for worker in info['workers']:
    if worker['time'] == 0:
        workable += 1
if workable < 10 and len(info['tasks']) == 0 and len(info['outsources']) == 0:
    print('zzz...')
    sys.exit(0)

if len(info['tasks']) == 0:
    task = query_taketask()
    print('take task', task['id'])
    query_outsource(task['id'], 1)
else:
    task = info['tasks'][0]
    print('use task', task['id'])
print(task)

for lim in [9,8,7,6,5,4,3,2,1]:
    worker_ids = []
    for worker in info['workers']:
        if worker['time'] == 0:
            if lim <= worker['speed'][task['pattern']]:
                worker_ids.append(worker['id'])
    if len(worker_ids) == 0:
        continue
    result = query_assign(task['id'], worker_ids)
    if result is not None:
        break
    else:
        wait(0.05)
else:
    print('fail')
```

もちろんよい順位を取りたいので必死で考えるが、特に何も思い付かないので、twitterで色々呟く。
ちょくだいさんときゃんちさんが来る。2位を大きく離し1位を独走していたので外から見たらすごく強い人に見えるのだろうが、普段の結果を知っている自分としてはほとんど余裕はなかった。

残り1時間と少しぐらいのところで、1位から転落。
やっぱり焼き肉奢れなかったなあ、みたいなことを考えながら眺めていた。
以降順位は単調に減少し続ける。最終的に7位で踏み止まれた。

最終的なコードは以下。最初から最後まで、ひたすら愚直に仕事をし続けただけであった。
社員は一切解雇していない。

``` python
#!/usr/bin/env python3
import urllib.request
import time
import os
import random
import json
import sys
import traceback
import math
import argparse

from common import *

info = query_getinfo()
print('id\ttime\texp\tspeed')
for worker in info['workers']:
    print('{}\t{}\t{}\t{}'.format(worker['id'], worker['time'], worker['exp'], ' '.join(map(lambda x: str(x).rjust(2), worker['speed']))))
for task in info['tasks']:
    print(task)
for task in info['outsources']:
    print(task)

out = query_getout()
print('id\ttime\tload\tpattern\treward')
for task in out['outsources']:
    print('{}\t{}\t{}\t{}\t{}'.format(task['id'], task['time'], task['load'], task['pattern'], task['reward']))

workable = 0
for worker in info['workers']:
    if worker['time'] == 0:
        workable += 1

if workable > 2:
    task = query_taketask()
    print('take task', task['id'])
    query_outsource(task['id'], int(task['reward'] * 0.9))
    info['tasks'].append(task)

for lim in [9,8,7,6,5]:
    for task in info['tasks'] + info['outsources']:
        worker_ids = []
        for worker in info['workers']:
            if worker['time'] == 0:
                if lim <= worker['speed'][task['pattern']]:
                    worker_ids.append(worker['id'])
        if len(worker_ids) == 0:
            continue
        result = query_assign(task['id'], worker_ids)
        if result is not None:
            print('get  reward', task['reward'])
            print('escape risk', task['risk'])
            sys.exit(0)

print('\tid\ttime\tload\tpattern\treward')
for task in out['outsources']:
    if task['reward'] / task['load'] < 0.07:
        continue
    print('try out {}\t{}\t{}\t{}\t{}'.format(task['id'], task['time'], task['load'], task['pattern'], task['reward']))
    for lim in [9,8,7,6,5]:
        worker_ids = []
        for worker in info['workers']:
            if worker['time'] == 0:
                if lim <= worker['speed'][task['pattern']]:
                    worker_ids.append(worker['id'])
        if len(worker_ids) == 0:
            continue
        result = query_assign(task['id'], worker_ids)
        if result is not None:
            print('get  reward', task['reward'])
            sys.exit(0)
```

``` python
import json
import os
import random
import sys
import time
import traceback
import urllib.request

def urlopen(url): #=> str or None
    try:
        res = urllib.request.urlopen(url, timeout=1)
    except Exception:
        traceback.print_exc()
    else:
        return res.read().decode()

def query(t,u=''): #=> str or None
    url = 'https://game.coderunner.jp/{}?token={}{}'.format(t,token,u)
    print(url)
    result = urlopen(url)
    # print(result)
    return result

def wait(sec=1.0):
    time.sleep(sec)

with open('token') as fh:
    token = fh.read().rstrip()

def query_taketask():
    result = query('taketaskJson')
    return json.loads(result)
def query_getinfo():
    result = query('getinfoJson')
    return json.loads(result)
def query_assign(task, workers):
    result = query('assign', '&task={}&worker={}'.format(task, ','.join(map(str,workers))))
    print(result)
    return result # str
def query_outsource(task, order_reward):
    result = query('outsource', '&task={}&orderReward={}'.format(task, order_reward))
    print(result)
    return result # str
def query_getout():
    result = query('getoutJson')
    return json.loads(result)
def query_change(workers):
    result = query('change', '&worker={}'.format(','.join(map(str,workers))))
    return json.loads(result)
```

私の結果に関して、考察の点では平均以下で、ただコーディングの速さだけで押し通せてしまっただけ、という印象を受ける。
競技の界隈はc++しか使えないという人も少なくないので、そこそこの実装力にpythonやshellscript等への慣れさえあれば、序盤の1位は取れてしまう。
そこに、アルゴリズムの工夫の影響が比較的鈍いという条件が加わると、最終の順位もそれなりのものになるようだ。
ただし、1位を狙うのであれば、やはり最初の1時間は全て紙の上での考察に費すなどすべきであったように思う。
来年は1位を取りたい。

## 本戦後

初めての賞金。嬉しい。

懇親会。klabドリンクでなかった理由を聞いたりCODE VSの開催の予定を聞いたりしてたら、トートバッグが貰えた。
複数の企業の人から、放送で映ってたね、twitterで実況してたの見てたよ、という報告を頂く。
なんだか恥ずかしい。
他の参加者ともわいわい。アメリカに行った話が面白かった。

帰宅は夜行バス。賞金を戴けるのなら新幹線でもよかったかなあ、と思いながら乗った。

## 要望

アンケート用紙に書き忘れたやつです。

-   翌朝帰宅して、生放送を見てみようかなと思ったら権限不足を理由にニコニコ動画に拒否された。
    せっかくの良いコンテンツなので、youtube等で公開してくれればいいのになと思う。

-   プログラム更新通知のapiが存在した。
    気が向いたときに適当にブラウザから叩いていた。
    面白い機能だと思ったが、参加者から一切その効果が見えないのはもったいないと思う。
    プログラムを更新したときに押して欲しいとのことであったが、当日の朝でもよいのでその存在を知らせてくれていれば、vim pluginでそのようなものを書いて配布するなどできるので、事前に情報があってよかったと思う。

-   この形式のコンテストはすごく面白いので、もっと頻繁にやってほしい。
