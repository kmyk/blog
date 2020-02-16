---
category: blog
layout: post
date: 2015-03-03T17:29:02+09:00
tags: [ "vim", "shell" ]
---

# vim芸としてのshell芸

vimはcommandを実行しその結果を埋め込む機能があります。便利です。なのでshell芸してみようと思いました。

しかしvim内から呼ぶ意味を考えるとfileの内容を入力にする他ないので派手さが無い。正直なところvim芸ともshell芸とも呼べるか怪しい。

<!-- more -->

## 基本

### 実行

``` vim
:!COMMAND ARGS...
```

ただ実行する。

-   `:!g++ %`
    -   g++でcompile `%`はfilepathに展開される

### 挿入

``` vim
:r!COMMAND ARGS...
```

cursor位置に出力結果を挿入する。基本ではあるが便利。

-   `:r!ls`
    -   current directoryの内容物を挿入
-   `:r!date`
    -   時刻の挿入

### 置換

``` vim
:RANGE!COMMAND ARGS...
```

選択範囲を標準入力から与え実行し出力結果で置き換える。

よく使われる`RANGE`には:

-   `.` 現在行
-   `'<,'>` 選択範囲
-   `%` 全行

がある。

-   `:.!bc`
    -   現在行を数式として計算
-   `:'<,'>!rev`
    -   選択範囲の各行を反転
-   `:%!expand`
    -   tabをspaceで置換

### 他

-   `/bin/sh`の範囲内なら何でも書けるようだ
    -   `:r!( for i in $(seq 10) ; do echo -n $i ; sleep 0.1 ; done ; echo ) ;`などすら動く
    -   `:r!echo $0`すると分かるが`/bin/sh`が走っている
    -   もちろん`/bin/sh`の中身に依存する
    -   `set shell=/usr/bin/bash`などで変更できる
-   `%`,`#`がvimに食われる
    -   `\%`,`\#`で抑制できる。`#`はさらにshにも解釈されるので注意
-   `\`,`''`,`""`はどれも基本的にvimを透過する

## 応用

-   `:.!ghc -e "$(cat)"`
    -   現在行をhaskellの式として実行
-   `:.!ruby -e "$(cat)"`
-   `:.!python -c "$(cat)"`
-   `:%!awk 'NR\%2==1'`
    -   奇数行を削除
    -   vimの`%`は展開されるため`\%`であることに注意
    -   awkのNRは1-basedであることに注意
-   `:%!grep .`
    -   空行を削除
    -   空白文字があると消えないのが嫌なら`:%!grep [^[:space:]]`
-   `:'<,'>!xargs touch`
    -   選択範囲の各行の名前でfileを作成
-   `:'<,'>!column -t`
    -   table整形
    -   Align.vimの代わりに
-   `:.,.+9!paste - <(seq 10)`
    -   現在行以下10行の末尾に行番号付与
    -   要bash
-   `tac`
-   `rev`
-   `sort`
-   `uniq`
