---
layout: post
redirect_from:
  - /writeup/long/codingame/codingame-hypersonic/
  - /blog/2016/10/03/codingame-hypersonic/
date: "2016-10-03T17:47:06+09:00"
tags: [ "competitive", "writeup", "codingame", "marathon", "game", "beam-search" ]
"target_url": [ "https://www.codingame.com/contests/hypersonic" ]
---

# CodinGame Hypersonic

$3$位。うれしい。

English version (summary) is here: <https://www.codingame.com/forum/t/hypersonic-feedback-strategy/2067/27>.

## problem

普通のボンバーマン。
一定時間生き残ったプレイヤー同士では、壊した障害物の数で順位を付ける。

## implementation

<https://github.com/kmyk/codingame-hypersonic>

## solution

強文脈[^1]ゲー。
丁寧にsimulationを書いて普通にbeam searchした。

-   禁止手の探索 <sup>[code](https://github.com/kmyk/codingame-hypersonic/blob/d1a43005327a1bd486909fc7b45d2c07ad252aeb/Answer.cpp#L641)</sup>
    -   それを選ぶと確実に死んでしまうような手を探す (実装したのは$1$手目のみ)
    -   相手が爆弾を置くことも考慮する (実装したのは$1$ターン目のみ)
-   beam search <sup>[code](https://github.com/kmyk/codingame-hypersonic/blob/d1a43005327a1bd486909fc7b45d2c07ad252aeb/Answer.cpp#L666)</sup>
    -   多様性のため、同じマスに居る状態の数に制限をかけた
        -   けっこう有効ぽい
    -   同一盤面除去も簡単にしておいた
    -   状態更新ごとに死に手でないか確認した
        -   重いが、これをしないと評価上はよいが実行不能な手が発生してしまうので、必要
        -   爆弾の設置と爆発の時間差を埋める策のひとつ
    -   各種パラメタはあまり調整できていない
-   評価関数 <sup>[code](https://github.com/kmyk/codingame-hypersonic/blob/d1a43005327a1bd486909fc7b45d2c07ad252aeb/Answer.cpp#L530)</sup>
    -   壊した箱の数、その見込み、およびその積算
        -   simulateした爆風の範囲から推定し、壊せる見込みの箱にも報酬
            -   爆弾の設置と爆発の時間差を埋める策のひとつ
            -   かなり有効
        -   早いターンで壊すことにも報酬がかかる
    -   取得アイテムの数
        -   小さな離散値なので具体的に指定できた
    -   中央付近は箱が多いから近づくべきだね、という報酬 (効果不明)
    -   最悪ケースが潰れることを祈って、乱数による小さな報酬 (効果不明)
    -   各種パラメタはあまり調整できていない

## 既知の問題点

-   即死は回避するが緩やかな詰みは回避しない
    -   同じターンに相手が爆弾を置くと死ぬ動作は排除したが、次以降のターンの場合は未実装ということ
    -   実装しかけていたがバグってそのままになった
-   遠くの箱を壊しにいかない
    -   探索ターン数以内で届く箱しか考慮していないため
    -   箱に近づくことに報酬与えるなどが考えられるが、パラメタ調整が面倒
-   敵を倒すための動作をしない
    -   敵も動くため詰みを判定する必要がある
    -   実装が後回しになった
    -   相手を箱にすると殺しにいくらしい[^2]

## 試せなかったこと

探索の$1$ステップを$1$ターンから$1$イベントにする、のを試したかった。
この場合イベントとは主に爆弾の設置とアイテムの取得。
一貫性がないと有効な手にならないという問題が解決すると予想している。確実に前進[^3]というやつ。

実装量は少なくはないので、時間がなかった。
$1$位と$2$位の$2$人はこれではと推測している。


他:

-   Chokudai search[^4]
    -   別の手段で多様性を得ており、競合するため優先度は低いと判断した
    -   時間が余ったら試してはいたと思う
-   Monte Carlo木探索
    -   一貫性がないと有効な手にならないので、どうランダムにするか難しそうだと思った

## その他

-   何時もの出落ちだと思ってたらそのまま$3$位で終わったので驚いている
-   3rd Place の Win prizes は T-Shirt と Contest painting 900x600mm らしいのですが、つまりでかい板が貰えるのだろうか。それはちょっと困る
-   $3$位以下は団子なのに比べて、$1$位と$2$位の人が強すぎ
-   参考にしようと他の人のコードを眺めたけれど、長くてだめだった


[^1]:   <https://twitter.com/colun/status/626914870932303876>, <https://twitter.com/colun/status/765392155804217344>
[^2]:   <https://twitter.com/nosnosnos/status/782644947287552000>
[^3]:   <http://qiita.com/takapt0226/items/b2f6d1d77a034b529e21>
[^4]:   一般の名称はbeam stack searchらしいね: <https://en.wikipedia.org/wiki/Beam_stack_search>, <https://twitter.com/chokudai/status/744508524655325185>
