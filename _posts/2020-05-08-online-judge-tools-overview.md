---
category: blog
layout: post
date: 2020-05-08T00:00:00+09:00
edited: 2020-09-28T00:00:00+09:00
tags: [ "competitive" ]
---

# online-judge-tools の全体像 (2020 年 5 月)

## TL;DR

2020 年 5 月現在、以下のような構造になっています。

-   [online-judge-tools/](https://github.com/online-judge-tools)
    -   [oj](https://github.com/online-judge-tools/oj)
        -   `oj` コマンド: 競プロの問題を解く際の定型作業を自動化する。特に、ストレステストの実行を補助する
        -   ([nodchip](https://atcoder.jp/users/nodchip) の [OnlineJudgeHelper](https://github.com/nodchip/OnlineJudgeHelper) をかなり参考にして設計された)
    -   [verification-helper](https://github.com/online-judge-tools/verification-helper)
        -   `oj-verify` コマンド: 競プロ用ライブラリの verify やドキュメントの生成を自動化する
        -   `oj-bundle` コマンド: 複数ファイルに分割して書かれたライブラリをひとつにまとめて提出できるようにする
        -   ([beet](https://atcoder.jp/users/beet) と [tsutaj](https://atcoder.jp/users/tsutaj) がたくさん貢献してくれた。[yosupo](https://atcoder.jp/users/yosupo) の [Library Checker](https://judge.yosupo.jp/) の存在も大きい)
    -   [template-generator](https://github.com/online-judge-tools/template-generator)
        -   `oj-template` コマンド: 競プロの問題を解析し入出力パートを自動生成する
        -   `oj-prepare` コマンド: 自動生成したファイルの配置やテストケースのダウンロードを一括でする
        -   ([kyuridenamida](https://atcoder.jp/users/kyuridenamida) の [atcoder-tools](https://github.com/kyuridenamida/atcoder-tools) を参考にして設計された)
    -   [api-client](https://github.com/online-judge-tools/api-client)
        -   `onlinejudge` module (Python ライブラリ): サンプルダウンロード機能やコード提出機能の本体を提供する
        -   `oj-api` コマンド: 派生ツールの開発者向けに JSON interface を提供する
        -   ([Jasperr](https://codeforces.com/profile/Jasperr) の [Competitive Companion](https://github.com/jmerle/competitive-companion) の影響を受けている)


## これなに

この記事は online-judge-tools とその派生物について、それらが何であるか、またどのように開発されてきたのかを説明します。
特に、関連する外部のプロジェクトとの関係や私以外のコントリビュータの貢献を明確にすることを意図しています。


## 対象読者

-   online-judge-tools の開発への参加に興味がある人
-   online-judge-tools と他のツールとの関係を知りたい人


## [online-judge-tools/oj](https://github.com/online-judge-tools/oj) リポジトリ

[online-judge-tools/oj](https://github.com/online-judge-tools/oj) リポジトリでは `oj` コマンドが開発されています。

### `oj` コマンドとは

`oj` コマンドは競プロの問題を解く際の定型作業を自動化するためのコマンドです。
ただし自動化の目的は「便利にすること」ではなく「レートを上げること」です。
以下のサブコマンドを提供します。

-   `download`: サンプルケースをダウンロードします
-   `test`: ダウンロードしたサンプルケースを使ってテストをします
-   `submit`: コードを提出します
-   `generate-input`: ジェネレータを受け取り、テストケースの入力を生成します
-   `generate-output`: 入力のみのテストケースと愚直解を受け取り、テストケースの出力を生成します
-   `test-reactive`: ジャッジプログラムを受け取り、インタラクティブ問題のテストをします

`oj` コマンドをそのまま使ってもレートはほとんど上がらないことに注意してください。
自動でサンプルを試せばミスが減りかつサンプルを試すのをサボることを防げたり、自動で提出をすれば提出先問題や言語の選択ミスを防げ、多少はレート上昇に寄与するでしょう。
しかし、これによるレート上昇は誤差程度でしょう。
自動でサンプルをテストしても手動でサンプルをテストしてもサンプルが一致するかどうかの結果は同じですし、自動提出したコードも手動提出したコードも AC するかどうかは同じです。

`oj` コマンドを使ってレートを上げるには、自分でテストケースを追加することが重要です。
提出前に `test/` ディレクトリ内に手動でいくつかテストケースを追加すれば WA や RE が防げます。
ランダムケースのジェネレータと愚直解を書きストレステストを行えばより多くの WA や RE を防げ、また効率よくデバッグをすることができます。
サンプルが弱い場合などに、これらはレート上昇により直接的に役立つでしょう。

詳細な使用方法などについては本体のドキュメント [introduction.ja.html](https://online-judge-tools.readthedocs.io/en/master/introduction.ja.html) を読んでください。


### 歴史

私が競プロを始め、現在の `oj` コマンドと同等のことをする小さなシェルスクリプトをとりあえず書いてしばらく使って限界に気付いたあと、もう少しましな既存のツールを探しました。
このときはまだ (少なくとも日本の競プロ界隈には) 自動化ツールは [nodchip](https://atcoder.jp/users/nodchip) による [OnlineJudgeHelper](https://github.com/nodchip/OnlineJudgeHelper) (2011年から開発されている) しか見つかりませんでした。
OnlineJudgeHelper は、必要な機能は一通り揃えておりかつ対応するオンラインジャッジの数も多い良いツールであり、私もこれを使い始めました。
しかし、いくつかプルリクを出しながらしばらく使い続けていると、OnlineJudgeHelper には「不安定である」という致命的かつ修正困難な欠点があることが分かってきました。
しばしばサンプルケースの誤検出があり「サンプルケースでのテストが通らず困っていたら、自分のコードのバグではなく、実はダウンロードされたサンプルケースが間違っていた」という事態が起こります。コンテスト中に発生して 1 時間ぐらい溶けたりします。
これに耐えられなくなり、OnlineJudgeHelper の長所をそのままに短所をすべて改善するべく自分ですべて書き直してできたのが online-judge-tools です。

また、名前やログ出力の形式は CTF 用のツールである [pwntools](https://github.com/Gallopsled/pwntools) の影響を受けています。

初期のものは様々な実験的機能を含んでいました。コードゴルフ用の統計情報を出力するサブコマンドや順位表の情報を取得するサブコマンドなどがありました。しかし、非本質的な機能はユーザにとっても開発者にとっても邪魔でしかないので、現在に至るまでにすべて削除されました。

### 現在

特に新機能の追加の予定はなく、現在はメンテのみをしています。
便利さはあくまでレートを上げるための手段であって目的ではないと考えて開発がされており、気の利いた (あるいは、お節介だと感じる人がいるような) 機能を足すことよりも、最低限の機能を確実に動かす (そして、そのような状態を保ち続ける) ことを重視してメンテされています。

今後の課題は以下です。コントリビュータとしては、メンテの継続性なども考慮した上での総合的なユーザエクスペリエンスの議論ができる人や、直接のユーザサポートが可能な人が求められています。

-   バグではないが使いにくい点の発見し修正する (たとえば「エラーメッセージが微妙に分かりにくい」など)
-   ユーザサポートやドキュメントの整備をする (たとえば「`oj` コマンドを使いたいがそもそも Python がインストールできない」みたいな人は多いが、そのような人もサポートしていきたい)


## [online-judge-tools/verification-helper](https://github.com/online-judge-tools/verification-helper) リポジトリ

[online-judge-tools/verification-helper](https://github.com/online-judge-tools/verification-helper) リポジトリでは `oj-verify` コマンドと `oj-bundle` コマンドが開発されています。

### `oj-verify` コマンドとは

`oj-verify` コマンドは、GitHub 上で管理されている競プロ用ライブラリの verify とドキュメントの生成を自動化します。
また [web installer](https://online-judge-tools.github.io/verification-helper/installer.ja.html) という形で、できる限り簡単に自動化が導入できるようになっています。

verify のためには [examples/union_find_tree.yosupo.test.cpp](https://github.com/online-judge-tools/verification-helper/blob/a30aa3c0dce9b22beb662045635f23949997167d/examples/union_find_tree.yosupo.test.cpp) のように、実際のオンラインジャッジへの提出コードを (提出先 URL を記載した上で) リポジトリ内に含めておきます。
そのようなコードがリポジトリに push されると、GitHub Actions 上で `oj-verify` コマンドが実行されます。
`oj-verify` コマンドは、提出先のオンラインジャッジから自動でテストケースを取得し、実際に実行してみて AC するかどうかを確認してくれます。

ライブラリの verify 状況は <https://online-judge-tools.github.io/verification-helper/> のような自動生成されたページから確認することができます。Markdown でドキュメントを書いておくといい感じに埋め込んでくれたりもします。


### `oj-bundle` コマンドとは

複数ファイルに分割して書かれたライブラリをひとつにまとめて提出できるようにするための `oj-bundle` コマンドを提供します。
これがないと、ライブラリを利用したコードの提出が面倒です。

また、ライブラリを `#include "..."` で呼び出せるようになるので、ライブラリ用のスニペットの管理が不要になります。

### 歴史

古くから競プロライブラリ上で CI を回したりドキュメントを自動生成する発想は知られていました (例: [asi1024/competitive-library](https://github.com/asi1024/competitive-library), [asi1024/red-baron](https://github.com/asi1024/red-baron))。
これを行うのに `oj` コマンドを流用すると便利だとして私があるドキュメントを書き、これに [beet](https://atcoder.jp/users/beet) が食いつきました ([GitHub Actions でライブラリの自動 verify  - beet&#39;s soil](https://beet-aizu.hatenablog.com/entry/2019/09/05/191828)) ([beet のライブラリ](https://beet-aizu.github.io/library/)は verify 用のファイルだけで現在 300 個を越えており、当時でも最低 100 個はあったはず)。
このころは `test.sh` という小さなシェルスクリプトが用いられていました。
私と [beet](https://atcoder.jp/users/beet) が「誰でも簡単に導入できるようにしたいよね」という話をしていたところ、ちょうど GitHub Actions が正式リリースされた (2019年11月) ので、古い `test.sh` を置き換える形で開発が始まりました。
また、同時期に [yosupo](https://atcoder.jp/users/yosupo) によって開発された [Library Checker](https://judge.yosupo.jp/) の存在も開発のきっかけのひとつです。

巨大ライブラリを擁する [beet](https://atcoder.jp/users/beet) による dogfooding と [tsutaj](https://atcoder.jp/users/tsutaj) による見た目のよいドキュメントは online-judge-verify-helper の方向性に大きな影響を与えています。
元々の `test.sh` は Travis CI 上でかつごく単純な CI のみを想定していましたが、[beet](https://atcoder.jp/users/beet) の独自の拡張がマージされ大規模ライブラリに対応しかつ GitHub Actions で動くようになり、また [tsutaj](https://atcoder.jp/users/tsutaj) が独自で開発していたドキュメント生成機能がマージされました。
特に [tsutaj](https://atcoder.jp/users/tsutaj) によるドキュメント生成機能の影響は大きく、(少なくとも私の中では) これによって「単なる verify のためだけのツール」だったものが「verify を通して、競プロerのライブラリの近代化 (ファイルに分割する、テストを書く、ドキュメントを書く、など) を促すためのツール」に変化したように思います。

当初は online-judge-verify-helper という名前で開発されていましたが、"verify helper" の部分が和製英語だということが指摘され "verification helper" に改名されました。これにより正式名称としては online-judge-verification-helper あるいは Online Judge Verification Helper になったのかなと思っていますが、正確なところはよく分かりません。「かっこいい代わりに中身が何なのか推測できない固有名詞」でなく「一般の単語を並べた安直で説明的な名前」を使っていることが原因です。歴史的経緯があったり単純に長かったりするので、verify-helper や verification helper と呼べば十分だと考えています。

### 現在

少なくとも C++ については、基本的な機能はすべて揃いそれなりに安定してきています。

今後の課題は以下です。コントリビュータとしては、熱心にライブラリを整備している人が求められています。その中でも特に、自分の整備したライブラリを他人に使ってほしいと思っている人だとなおよいです。

-   ユーザを増やす (verification helper が普及すると、テストケースを積極的に公開してくれるサイトが増えたり、Library Checker の問題が増えたりしやすい)
-   テストを書く (開発者らの個人の競プロライブラリでの dogfooding が最大のテストというのが現状です)
-   対応言語を追加する (対象の言語のファイルの依存関係の解析などをするので、対象の言語の仕様に関する知識が必要)
-   ドキュメント生成機能を拡張する (Jekyll によるより柔軟なカスタマイズを許したり、verify にかかった時間を表示するなど)
-   ドキュメント生成機能をリファクタリングする (機能には価値があるので消せないがコード自体にはあまり触れたくないようなものになっていて、他の機能の追加を阻害しています)


## [online-judge-tools/template-generator](https://github.com/online-judge-tools/template-generator) リポジトリ

[online-judge-tools/template-generator](https://github.com/online-judge-tools/template-generator) リポジトリでは `oj-template` コマンドと `oj-prepare` コマンドが開発されています。

### `oj-template` コマンドとは

`oj-template` コマンドは、競プロの問題文を解析し、自動生成された入出力パートを含んだテンプレートを出力します。
たとえば次のようなもののテンプレートが出力できます。

-   C++ の解法用コード (`main.cpp`)
-   Python の解法用コード (`main.py`)
-   Python のランダムケースのジェネレータ (`generate.py`)
-   他にも:
    -   C++ のランダムケースのジェネレータ (`generate.cpp`)
    -   C++ の解法用コード (高速入出力使用) (`fastio.cpp`)

入出力パートの自動生成はよくあるミス (例: Codeforces で `std::endl` を使う) を防ぐ効果があります。
もちろん、自分の使っている言語での入出力の方法を正しく理解している人にとっては、レート上昇にはあまり役立ちません。
また速度面でも、入出力パートは手書きしても数十秒程度であること、精度を完璧にするのが不可能であり生成結果の確認が必要なことから、レート上昇の役には立たないでしょう。

ランダムケースのジェネレータも数分で書けますが、こちらは重要です。
ランダムケースのジェネレータは入出力パートと違って必須ではないため、人間は面倒がってこれを書かずに省略しがちなためです。
ジェネレータの自動生成は、この面倒を低減しストレステストを行う頻度を上げることができ、この意味でレート上昇に役立ちます。


### `oj-prepare` コマンドとは

自動生成したファイルの配置やテストケースのダウンロードを一括でしてくれる `oj-prepare` コマンドを提供します。
レート的な恩恵はありませんが、楽ができます。


### 歴史

私が知る限り最初に入力パートの自動生成機能を実装したのは online-judge-tools ですが、純粋に入力パート
2018年12月ごろに (online-judge-tools と独立に) [atcoder-tools](https://github.com/kyuridenamida/atcoder-tools) に入力パート生成機能が実装されました ([問題文から入力コードを自動生成するツール(atcoder-tools)の紹介 - kyuridenamidaのブログ](http://kyuridenamida.hatenablog.com/entry/2018/12/27/091225))。
atcoder-tools のものは (1.) 入力パート以外のテンプレートも同時に生成し、また (2.) サンプルケースのダウンロードと同時にコード生成を行うというふたつの性質から、多くのユーザが何も自然に利用できるという点でとても優れていました。
[kyuridenamida](https://atcoder.jp/users/kyuridenamida) と「atcoder-tools を Codeforces でも使いたいので online-judge-tools とマージあるいは連携しよう」という議論をしていましたが、ゆっくりしている間に atcoder-tools がより大きくなり、atcoder-tools を基本とした大規模な修正は困難になってしまいました。
また、入力パートだけでなく出力パートも生成したい、ランダムケースのジェネレータも生成したいと私は考えていました。
そこで atcoder-tools を参考にしながら再設計し実装されたのが online-judge-template-generator です。


### 現在

一通り動くようにはなりました。しかしまだ完成度は高くなく、これから上げていこうというところです。

今後の課題は以下です。コントリビュータとしては、コンパイラを書けたり自然言語処理ができたりする人が求められています。

-   対応言語を追加する (内部の木構造を組み換えてコードを生成 (かなりコンパイラぽい))
-   問題の制約を解析する (たとえば「これらの変数 `V` `E` `u_1` `v_1` `...` `u_E` `v_E` はグラフ $G = (V, E)$ を表現している」とかを認識したい (自然言語解析))
-   解析や生成の精度を向上させる

ランダムケースのジェネレータを生成する部分に関しての最終目標は、問題ページから制約も認識して入力される変数の意味を解析し、自動で強いテストケースを出力することです。
たとえば、ある変数の組 `int n;` `vector<int> u(n - 1);` `vector<int> v(n - 1);` が全体でひとつの木を表現していることを認識して、ほとんど直線であるような木を使ったテストケースを自動で出力するなどがしたいです。


## [online-judge-tools/api-client](https://github.com/online-judge-tools/api-client) リポジトリ

[online-judge-tools/api-client](https://github.com/online-judge-tools/api-client) リポジトリでは `onlinejudge` module と `oj-api` コマンドが開発されています。

### `onlinejudge` module とは

`onlinejudge` module は、`oj` コマンドの内部で使われているサンプルダウンロード機能やコード提出機能の本体です。

この module は勝手に web scraping をしているだけなので、積極的にメンテをし続ける必要があります。つまり、AtCoder や Codeforces に機能が追加され更新があるたびに壊れます。

### `oj-api` コマンドとは

`oj-api` コマンドは `onlinejudge` module の wrapper であり、競プロ用ツールの開発者向けに JSON を出力します。
[Competitive Companion](https://github.com/jmerle/competitive-companion)) が出力する JSON と互換性があります。

### 歴史

`onlinejudge` module はつい最近まで <https://github.comkmyk/online-judge-tools> リポジトリで開発されていました。
このリポジトリには、`oj` コマンドというエンドユーザ向けの部分と、`onlinejudge` module という他のツールの開発者向けの部分とが混在していました。これらは依存関係はあるのものの基本的には独立なものです。これを分割してできたふたつのうち開発者向けの側が [online-judge-tools/api-client](https://github.com/online-judge-tools/api-client) です。
特に、`oj-api` コマンドという形で Competitive Companion と互換性のある JSON interface を提供するだけでなく、リポジトリを分けることによってそれが提供されていることを明確に示す必要がありました。

このような分割は、短期的にはユーザにとっては何の利益もなくただ混乱が起こるだけですが、中長期的には意味があると予想しています。
これは Competitive Companion のエコシステムと合流する余地が生まれるためです。
Competitive Companion は競プロの問題のサンプルケース取得などを行うブラウザ拡張であり、ブラウザ拡張であるので「別途のログイン作業が不要」かつ「今ブラウザで開いている問題のサンプルケースの取得をするという操作ができる」という点で優れています。
これと協調できるようにしておくのは競プロ界隈全体にとって有益なはずです。


### 現在

`onlinejudge` module 部分は完成しています。`oj-api` コマンドはこれから完成度を上げていく段階です。

今後の課題は以下です。コントリビュータとしては、web scraping とライブラリ開発の作法に詳しくメンテに関する経験が豊富な人が求められています。

-   対応オンラインジャッジを増やす (特にコンテスト情報の解析)
-   動作状況の監視し修正する (オンラインジャッジ側のアップデートで仕様が変わって動かなくなることが定期的にあるため)
-   分割作業の続きと後始末をする (テストの新形式への移行など)


## [online-judge-tools](https://github.com/online-judge-tools) organization

[online-judge-tools](https://github.com/online-judge-tools) organization は online-judge-tools 関連のリポジトリを置いておくための GitHub organization です。

### 歴史

online-judge-tools 関連のリポジトリはこれまですべて私の個人の GitHub アカウントの下に置いて開発をしていましたが、ユーザ数も関連リポジトリも増えてきたために GitHub organization を作りました。
ユーザにとっての利益としては、バス係数を 2 以上にできることが挙げられます。
つまり、もし私が突然失踪したとしても、fork による分裂などの面倒なしに開発が続いてくれます。
このために必要な後任のメンテナを指名するなどの役は [yosupo](https://atcoder.jp/users/yosupo) にお願いしてあります。


## 感謝

本文中で名前を挙げた [nodchip](https://atcoder.jp/users/nodchip), [kyuridenamida](https://atcoder.jp/users/kyuridenamida), [beet](https://atcoder.jp/users/beet), [tsutaj](https://atcoder.jp/users/tsutaj), [yosupo](https://atcoder.jp/users/yosupo), [Jasperr](https://codeforces.com/profile/Jasperr) 以外にも、多くの人の貢献があります。

[fukatani](https://atcoder.jp/users/ryoryoryo111) には主に `oj` コマンドや `onlinejudge` module のメンテの手伝いをしてもらっています。いくつかの作業を任せていましたが、特にコードレビュー (具体的には、私がテストやコメントを書くのをさぼっていると「さぼるな」とレビューで指摘する) をやってもらっていたのが助かりました。
[kawacchu](https://atcoder.jp/users/kawacchu) は最近は多忙のため離れてしまいましたが、一時期は同様にメンテを手伝ってくれました。

[online-judge-tools/oj](https://github.com/online-judge-tools/oj) と [online-judge-tools/api-client](https://github.com/online-judge-tools/api-client) には 2020 年 5 月の時点で以下の人々からプルリクエストをもらっています。

-   [btk15049](https://github.com/btk15049)
-   [cgschu1tz](https://github.com/cgschu1tz)
-   [eggplants](https://github.com/eggplants)
-   [fukamachi](https://github.com/fukamachi)
-   [ganow](https://github.com/ganow)
-   [hachi-88](https://github.com/hachi-88)
-   [hamayanhamayan](https://github.com/hamayanhamayan)
-   [kjnh10](https://github.com/kjnh10)
-   [knshnb](https://github.com/knshnb)
-   [kotatsugame](https://github.com/kotatsugame)
-   [nishanth2143](https://github.com/nishanth2143)
-   [njkevlani](https://github.com/njkevlani)
-   [pachicobue](https://github.com/pachicobue)
-   [pieceofeden](https://github.com/pieceofeden)
-   [serihiro](https://github.com/serihiro)
-   [uta8a](https://github.com/uta8a)
-   [yoshrc](https://github.com/yoshrc)

同様に [online-judge-tools/verification-helper](https://github.com/online-judge-tools/verification-helper) には以下の人々からプルリクエストをもらっています。

-   [chaemon](https://github.com/chaemon)
-   [key-moon](https://github.com/key-moon)
-   [morioprog](https://github.com/morioprog)
-   [sash2104](https://github.com/sash2104)
-   [southball](https://github.com/southball)

直接のプルリクエスト以外にも、バグや機能要望を報告する、使い方などで困っている他のユーザを助ける、紹介記事を書く、online-judge-tools と協調して動くプログラムを開発するなど、様々な形で多くの人からの貢献があります。これらもプルリクエストと同程度には重要な貢献ですが、貢献者の名簿が得られないため、名前を列挙することは省略します。


## おまけ: 将来

追加で、以下を作ろうとしています。

-   典型コーナーケースをいい感じに生成してくれるライブラリ
    -   星グラフっぽい木、ほとんど同じ文字の文字列、2 巾付近の自然数などの、典型コーナーケースを生成してくれるものがほしいです。作問およびストレステスト用です。いくつかの場合についてプロトタイプ ([`onlinejudge_random/__init__.py`](https://github.com/online-judge-tools/template-generator/blob/acd1b45410e938681c166b85def4e5afa1421a97/onlinejudge_random/__init__.py)) は作りましたが、そのまま放置されています。私の代わりに開発をしてくれる人がいたらいいなと思っています
-   競プロに使えるような C++ STL の永続版ライブラリや rollback-可能版ライブラリ
    -   `std::vector<int>` を `persistent_std::vector<int>` などのように置き換えて使える永続データ構造のライブラリであって、競プロ用に使えるものがほしいです。まだ何もしていません。私の代わりに開発をしてくれる人がいたらいいなと思っています
-   競プロの問題を自動で解くツール
    -   プロトタイプ ([kmyk/Jikka](https://github.com/kmyk/Jikka)) を実装したあと半年ほど放置していましたが、最近は再び実装の続きをしています。これについては私がやるしかないだろうなと思っています
