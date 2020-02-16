---
category: blog
layout: post
redirect_from:
  - /blog/2018/12/12/call-for-maintainers/
date: "2018-12-18T23:59:59+09:00"
edited: "2018-12-20T23:59:59+09:00"
tags: [ "competitive", "development", "github" ]
---

# 競プロ関連で作ったツールの紹介

## はじめに

これは [AtCoder関連サービス Advent Calendar 2018](https://adventar.org/calendars/2932) の19日目の記事です。
ツールを思い付きで適当にたくさん作ってたら収集が付かなくなってきたのでその整理と宣伝をします。

メンテナの募集も兼ねています。
バグの修正や仕様変更への追従が大変なので手伝ってくれる人がほしいです。
人助けをしてOSSコミッタを名乗ってみませんか？
まだ慣れていないならやり方も教えます。
よろしくお願いします。

## 作ったもの

### oj ([repo](https://github.com/kmyk/online-judge-tools))

AtCoderを含む複数のオンラインジャッジに対し、自動でサンプルケースの取得やテストや提出やその他の諸々をしてくれるコマンドラインツールです。
コンテストに参加する上で非常に重要な小道具です。
これがあるのとないのとではレートが $$100$$ ぐらいは変わる気がします。

片手を越える数のサービスと機能に対応しているので何もしないと端から壊れていきます。
「ドメインが変更された」とかなら楽な方で「いつの間にかログインのformにCSRF tokenが足されて動かなくなってたけど、ログインしなおす機会は少ないので長期間気付けない」「システム更新で旧APIが廃止されたので新APIに移行しないとだめ」「新APIに移行したけど新APIは旧APIと違って容量が多いとファイルの後ろの方を `..... (terminated because of the limitation)` として省略してくる」「サーバの負荷が高い時はなぜかencodingの指定が送られてこないので文字化けする」などの厄介なのが定期的に発生します。
想定されていない形でサービスを利用している以上、この手の状況は起こるべくして起こっているものなので諦めて修正をします。
バグに気付ければ修正はたいていすぐですが修正が面倒な場合は機能を削除してしまうことで修正とされがちです。

### AtGolfer ([@atgolfer1](https://twitter.com/atgolfer1), [repo](https://github.com/kmyk/atgolfer))

AtCoder上でのゴルフの記録更新を通知するTwitter botです。
超絶技巧を用いて書かれたコードがTLに流れてくるようになるので面白いです。
類似botに [@yukigolfer](https://twitter.com/yukigolfer), [@yukigolfer_pure](https://twitter.com/yukigolfer_pure) があります。

内部でAtCoder ProblemsのAPIを利用しています。
AtCoder Problemsのクロール速度の限界のためにコンテスト終了直後の通知が遅れることが問題となっており、
~~解決されればいいなあと思っています。実際に解決したい人はいるようなので待っていれば解決されるかもしれません。~~
[x20](https://atcoder.jp/users/x20) が解決してくれました。
ありがたい。
これが解決されたことにより連鎖的に通知の遅延も短くなりました。

### AtCoder dos2unix UserScript ([install](https://github.com/kmyk/atcoder-dos2unix-userscript/raw/master/index.user.js), [repo](https://github.com/kmyk/atcoder-dos2unix-userscript))

AtCoderへの提出の改行を CRLF でなく LF にするuserscriptです。
なんであれ $$1$$ バイトを削ることはコードゴルフにおいてとても重要です。
改行の差のみで最短コードを獲得することにどれほどの意味があるかは不明ですが、最短の獲得には文字通り必須です。

### 精進bot ([repo](https://github.com/kmyk/shoujin-slack-notifier))

対象者がその日に解いた問題を通知するSlackのbotです。
部内Slack上の `#shoujin` チャンネルで動いています。
他人の精進を見て「私もやらないとなあ」という気持ちになれるので便利です。
AtCoderとCodeforcesに対応しています。

作りが雑かつ修正のやる気がないのでとても不安定です。
AtCoder Problemsの不調やCodeforcesでGymの問題が解かれるなどがあると例外を吐いて落ちます。
解いた問題数のグラフなどを出力させたいのですがAPIの叩き方の問題によりできていません。
部活動やサークルごとにひとつずつこの手のbotが独立に開発されていそうですし、どこかがきちんと整備してSlack Appとして公開してほしいなあと思っています。

### TopCoder Marathon Match Rating Predictor ([install](https://github.com/kmyk/topcoder-marathon-match-rating-predictor/raw/master/rating.user.js), [repo](https://github.com/kmyk/topcoder-marathon-match-rating-predictor))

MMの暫定の順位表から予想されるレートの変化を計算して表示するuserscriptです。
MMでは気合と根性がかなり有効に働きます。
ゆえにレートを重要と考える人の場合はその変化を表示することはコンテストの成績に影響を与えます。あと提出ごとに一喜一憂するのは楽しいです。

完成度が $$7$$ 割くらいのところでMMを引退してそのままになっています。
順位表の2ページ目を見に行くようにするとか ~~`localStorage` に結果をキャッシュしておくとか~~ をするべきですがやる気が足りていません。
~~そもそもきちんと動いているのかの確認もできていません。~~
ちょっとやる気がでたので部分的にはやりました。

### TopCoder TimeZone UserScript ([install](https://github.com/kmyk/topcoder-timezone-userscript/raw/master/index.user.js), [repo](https://github.com/kmyk/topcoder-timezone-userscript))

MMのページ上の時刻をすべてJSTに変換してくれるuserscriptです。
時刻がすべてEDTで書かれてて分かりにくかったので作りました。
終了時刻の勘違いがあると困るのですこしだけ便利です。


## 作ったけどなかったことになったもの / まだ動いてるけど使われてないもの

-   MM系の問題のビジュアライザを簡単に作るためのフレームワーク ([repo](https://github.com/kmyk/longcontest-visualizer-framework))
    -   ビジュアライザが付いてない問題で使うために作りました。作ったはいいのですが数回しか使っていません。
-   yukicoderの問題をおすすめするサイト ([repo](https://github.com/kmyk/yukicoder-recommendation))
    -   データ集めて機械学習でリコメンデーションな感じをしたかったのですが、データを集める段階で飽きました。そもそもデータ数が少なすぎて無理でした。サーバの維持に費用がかかるので停止しました。
    -   知見は[KokiYmgch](https://atcoder.jp/users/KokiYmgch)が[Atcoder Finder](https://github.com/Koki-Yamaguchi/AtcoderFinder)を作る際のアドバイスに利用されました。なおこのサービスもいつの間にか消えていました。
-   精進の量をグラフにするwebアプリ ([page](https://kimiyuki.net/app/atcoder-shojin/), [repo](https://github.com/kmyk/atcoder-shojin-moving-average))
    -   問題数やRated-Pointの和を精進の量の指標とすると「ABCのAを埋める」が最適解になります。これでは良くないので、適切な可視化がほしいと思って作りました。その値に必然性がなく曖昧であることと、わざわざ見に行くのが面倒なことによりほとんど利用していません。
-   TopCoder Marathon Matchの点数を補数を取って見やすくするuserscript ([install](https://github.com/kmyk/topcoder-marathon-match-userscript-score-complement/raw/master/index.user.js), [repo](https://github.com/kmyk/topcoder-marathon-match-userscript-score-complement))
    -   「$$973725.24$$ 点から $$966377.98$$ 点になりました」と言われてもよく分かりませんが、 $$y = 10^6 - x$$ と変換して「$$26274.76$$ 点から $$33622.02$$ 点になりました」だと分かりやすそうだと思ったので作りました。しかしそもそも順位表の上の生の点数を見てる時点で何をやってもだめだということに気付いたのでほとんど使われませんでした。
-   brainfuckのコードをC言語としてコンパイルできるbrainfuckのコードに変換するスクリプト ([repo](https://github.com/kmyk/wrap-brainfuck))
    -   競プロの問題をbrainfuckで実装したけどなぜかサイト側が対応してなくて困ることはよくあると思います。そういうときに使うために作りました。AtCoderがbrainfuckに対応したので不要になりました。
    -   実はbefunge版もあります: [repo](https://github.com/kmyk/wrap-befunge)


## 作りたいもの

-   ojの提出機能の強化
    -   誤提出を危険視して避けてきましたが、マウスぽちぽちしての提出よりはましだと思うようになってきました。でも実装するのはつらい。
-   精進を通知してくれるSlack App
-   AtCoderへの提出結果のURLを渡すと WA や RE の原因を指摘してくれるサービス
    -   C++の初心者が書いたコードのバグはたいてい適切なツールを使ってサンプル入力を食わせてやれば原因が分かります。手軽かつ面白そうだとは思いますが、私自身が問題を解く際の役には立たないので後回しになっています。
-   愚直DPのコードを入力すると典型手法で加速してくれるプログラム
    -   累積和やセグ木やCHTをやるだけならやれると思うのですが、面倒が多いので構想のままになっています。実行をtraceしてMonge性を指摘したりできるぐらいになればかなり便利になる気はしています。
