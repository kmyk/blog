---
category: blog
layout: post
date: 2015-09-18T01:52:10+09:00
tags: [ "aspell", "command" ]
---

# aspell 覚書

## aspell(1): interactive spell checker

aspellはスペルチェッカーです。特にチェックだけでなく同時に訂正も手伝ってくれます。
`palyってこれplayでは？`、`difineってなんだよdefineだろ`みたいな質問に`はい` `はい` `はい`と答えるだけで全てよろしくしてくれるすごいやつです。

<!-- more -->

### 対話的

起動は以下。

``` sh
$ aspell check foo.tex
```

`--lang=en`とかを要求されるかもしれません。なお日本語は対応していません。


スペルミスがある場合、以下の操作で対話的に修正します。

-   `0-9` で その文字で置換
-   `r` で 自分で入力して置換
-   `i` で 無視
-   `a` で 無視 + 辞書に追加 (`~/.aspell.*.*`)

pathからtexだとかhtmlだとか判断して適切にしてくれるし、backupも取っておいてくれます。

### 非対話的

以下のように実行。

``` sh
$ aspell --mode=tex list < foo.tex
```

スペルミスの可能性がある単語を全て出力します。

基本はinteractiveであるためか、標準入力からしか読んでくれません。またそのせいでfileの種類の判別ができず、`--mode=tex`のように明示する必要があります。

Makefileにでも置いておくとよいでしょう。

---

# aspell 覚書

この記事は <del> 先日英語で発表したとき前日の夜に修正した部分でtypoしてaspell掛けずにそのまま使っちゃったのを反省し、 </del> Makefile内で自動で確認させたくて調べたので書きました。
