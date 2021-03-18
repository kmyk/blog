---
category: blog
layout: post
date: 2021-03-18T00:00:00+09:00
tags: []
---


# マラソンマッチのためのツールセットはどのようなものになるか

## TL;DR

-   Q. マラソンマッチ (あるいは AtCoder Heuristic Contest など) のためのツールセットであって高機能なものを考えたとき、どのようなものになるだろうか？
-   A. それは個人用のオンラインジャッジシステムのようなものになるだろう。

## はじめに

AtCoder Heuristic Contest が始まりました。
私もすこしずつこの手の長期コンテストに復帰していきたいと考えています[^red-touch-intai]。

さて、パソコン力で殴って優位に立てるなら殴っておきたいものです。
そのような事前準備について、考察や資料のまとめを置いておきます。

## 要件

マラソンマッチのためのツールに必要な機能を列挙してみましょう。
これには「並列実行」「可視化」「統計」「パラメタ最適化」「履歴管理」の 5 つを挙げられるはずです[^youken-hoka]。
それぞれの詳細は下で述べますが、つまりは書いたコードを「素早く」かつ「分かりやすく」評価して改善するための枠組みが求められています[^language-for-mm]。

### 並列実行

コア数の多い計算機を使って並列実行することはよく行なわれます。自分で購入してもよいですし、クラウドサービス (Amazon EC2 など) で借りてもよいでしょう。借りた場合は 64 コアのマシンが 1 時間 70 円くらいです[^ec2-price]。GitHub Actions 経由で自動実行されることもあります。

-   例:
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">はじめてRyzen 5950X買ってて良かったなと思いました(32スレッド並列パワーで5秒 * 1000テストケース)の実行が2分半くらいで終わる。 <a href="https://twitter.com/hashtag/AHC001?src=hash&amp;ref_src=twsrc%5Etfw">#AHC001</a> マラソン専用CPU</p>&mdash; きゅうり (@kyuridenamida) <a href="https://twitter.com/kyuridenamida/status/1371061507870621697?ref_src=twsrc%5Etfw">March 14, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
-   例:
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">GitHub に push するたび自動で 20 並列 1000 ケースでテストが走るようにしていました。再現確率が低いバグをうまく拾えるので便利でした。 <a href="https://twitter.com/hashtag/AHC001?src=hash&amp;ref_src=twsrc%5Etfw">#AHC001</a> <a href="https://t.co/zp63xICWwn">https://t.co/zp63xICWwn</a><a href="https://t.co/KrB4jHlfxV">https://t.co/KrB4jHlfxV</a></p>&mdash; kimiyuki@うさぎ🐇 (@kimiyuki_u) <a href="https://twitter.com/kimiyuki_u/status/1371059321182642179?ref_src=twsrc%5Etfw">March 14, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

### 可視化

参加者はコンテストごとに与えられたビジュアライザを修正して改良するのが通常です。また、これをするための汎用の枠組みを作っている人もいます。

-   例:
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr"><a href="https://twitter.com/hashtag/AHC001?src=hash&amp;ref_src=twsrc%5Etfw">#AHC001</a> お疲れ様でした．<br>暫定スコア 486.9 億点，148位でした．<br><br>焼き鈍しです．ときどき形を矯正したり破壊したりして，いいスコアになる state を探しました．<br>typescript でビジュアライザを作って，スコアが悪い問題を観察しながら進めていました．せっかくなので動画を貼ってみます． <a href="https://t.co/BxxjMkuJb6">pic.twitter.com/BxxjMkuJb6</a></p>&mdash; si💊 (@iiljj) <a href="https://twitter.com/iiljj/status/1371055428021407744?ref_src=twsrc%5Etfw">March 14, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
-   例:
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">これなんですけど、ちょっと整理して使いやすいように汎用用途でご利用できるようにgithubで公開しました(Marathon General Visualizer)。できるだけパソコン要素を減らそうと尽力はしましたがIDEなしで使いこなすのは難しそうな技術スタックになってしまった<a href="https://t.co/dXPbuLmnS5">https://t.co/dXPbuLmnS5</a><a href="https://twitter.com/hashtag/AHC001?src=hash&amp;ref_src=twsrc%5Etfw">#AHC001</a> <a href="https://t.co/5n9AnkS3Ia">pic.twitter.com/5n9AnkS3Ia</a></p>&mdash; きゅうり (@kyuridenamida) <a href="https://twitter.com/kyuridenamida/status/1371164033953320965?ref_src=twsrc%5Etfw">March 14, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
-   例:
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">専用のビジュアライザを作るほどでもないけど内部状態を動画で保存したい、というときのために簡易動画出力器を作りました。動画にしたい部分に描画命令を書くだけでそのまま C++ のコードから svg 動画を html 形式で出力します　意外と便利なので次回以降も活躍予定<a href="https://t.co/oHtKOFhqY2">https://t.co/oHtKOFhqY2</a> <a href="https://twitter.com/hashtag/AHC001?src=hash&amp;ref_src=twsrc%5Etfw">#AHC001</a> <a href="https://t.co/wLdKpitvR7">pic.twitter.com/wLdKpitvR7</a></p>&mdash; さはら (@shr_pc) <a href="https://twitter.com/shr_pc/status/1371121053330595840?ref_src=twsrc%5Etfw">March 14, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
-   例: [kmyk/longcontest-visualizer-framework](https://github.com/kmyk/longcontest-visualizer-framework)
-   例: [colun/gvc](https://github.com/colun/gvc)

### 統計

ICFPC においてはチーム内の専用の順位表 (「ダッシュボード」と呼ばれることが多い) が作られることが多いです。
個人戦のマラソンマッチにおいても、複数の提出間でのテストケースごとの傾向の差を観察することは有効です。

-   例:
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">私の ICFPC はダッシュボード作り(1日目)と複数 AI をとりまとめるスーパーバイザ作り(2,3日目)をやっていた感じだった。今回は AI 本体には手を出さない(チームメイトに任せる)と心に決めていたので自分の仕事に集中出来てよかった。</p>&mdash; Shuhei Takahashi (@nya3jp) <a href="https://twitter.com/nya3jp/status/630743782888112128?ref_src=twsrc%5Etfw">August 10, 2015</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
-   例:
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">ICFPCお疲れ様でした！こんなチームのダッシュボードつくってました。 <a href="https://t.co/ShNHpylgJ2">pic.twitter.com/ShNHpylgJ2</a></p>&mdash; がぁ君 (@mecha_g3) <a href="https://twitter.com/mecha_g3/status/894528840541773826?ref_src=twsrc%5Etfw">August 7, 2017</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>
-   例: [ICFPC 2019 にチーム Pigimarl として参加し世界 3 位をとりました &#124; RCO Ad-Tech Lab Blog](https://www.rco.recruit.co.jp/career/engineer/blog/rco_icfp_pc_2019_pigimarl/)

### パラメタ最適化

ハイパーパラメータ自動最適化フレームワークを用いてパラメータ調整をする試みもなされています。フレームワークとしては Optuna が有名です。

-   例:
    <blockquote class="twitter-tweet"><p lang="ja" dir="ltr">パラメータ最適化、今回はやってる余裕なかったけど<br>cpp<br>0. コマンドライン引数でパラメータを受け取る<br>python<br>1. subprocess から上を呼ぶ<br>2. joblib で 1 を並列化<br>3. optuna で 2 を目的関数にして最適化<br>みたいなことをいつもしてる (並列化は optuna 自体にもあったっけ？)</p>&mdash; koyumeishi (@koyumeishi_) <a href="https://twitter.com/koyumeishi_/status/1371240307208036359?ref_src=twsrc%5Etfw">March 14, 2021</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

### 履歴管理

コードの編集履歴を管理する際には Git が用いられます。
Git ではあるふたつの辞典のコードの差分を表示したり複数の変更をマージしたりできます。

-   例: <https://bitbucket.org/tomerun/marathon/src>
-   例: [kmyk/topcoder-marathon-match-100-same-color-pairs](https://github.com/kmyk/topcoder-marathon-match-100-same-color-pairs)

## 結論

これらの要件をすべて (あるいはいくつか) を満たすものはどのようになるでしょうか？
おそらくそれは「オンラインジャッジシステム」とかなり似たものになるはずです。
「コードを提出すると評価結果が返ってくる」という枠組みはまさにオンラインジャッジです。統計や最適化のためのいくつかの拡張が入るでしょう[^online-judge-with-visualization]し、実行環境はオフラインにあるかもしれませんが、大枠の理解としてはなおオンラインジャッジということになるように思います。

## おわりに

誰か作ってください。たのむ。

## 注釈

[^red-touch-intai]: 2 週間全力を捧げるのは単純にしんどいので、赤タッチしてすぐ引退してしまっていました。
[^ec2-price]: 2021 年 03 月 18 日時点で c6g.16xlarge (64 vCPU) が $0.6385/1時間 です ([料金 - Amazon EC2 スポットインスタンス - Amazon EC2 &#124; AWS](https://aws.amazon.com/jp/ec2/spot/pricing/))。
[^youken-hoka]: もちろん、まだ他にもあるかもしれません。
[^language-for-mm]: コードの自動生成をしたいという要求もありますが、今回はこれについては議論しません。事例としては [colun/mmlang](https://github.com/colun/mmlang) や[競技プログラミングの問題を自動で解きたい - うさぎ小屋](https://kimiyuki.net/blog/2020/12/09/automated-solvers-of-competitive-programming/) ([kmyk/Jikka](https://github.com/kmyk/Jikka)) などがあります。
[^online-judge-with-visualization]: 可視化の機能が組み込まれたオンラインジャッジとしてはすで CodingGame があります。
