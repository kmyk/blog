---
category: blog
layout: post
title: "radare2 使い方 メモ"
date: "2018-03-11T18:36:06+09:00"
tags: [ "ctf", "radare2", "tutorial" ]
---

しばらく触らないと忘れるしググっても節操なく命令を列挙してるだけのなにかしか見付からないので自分で書いた。
versionは2.4.0。

### radare2とは

binary editorかつdebugger。
vim+gdb あるいは CUI&OSS版IDA Pro のような何か。

### 使い方 最小限

how to install: <https://github.com/radare/radare2#install>

1.  `$ r2 ${FILE}` で起動
1.  準備として `aaa` 改行 `s main` 改行 `V` 改行 `p` と入力
1.  `j`, `k` で移動 / `1` $\dots$ `9` でjump

### noraml mode 基本

状態

-   `:q` 終了
-   `:?` help
-   `:V` visual modeへ移行
    -   `:v` でもよいっぽい

解析

-   `:a` `:aa` `:aaa` `:aaaa` 自動解析
    -   多い方が強い(そして遅い)
-   `:s sym.main` seek 移動
    -   この場合main関数へ飛ぶ
-   `:iI` checksec相当 情報表示
-   `:/ foo` file中からbyte列検索
-   `:? sym.main + 3` addressなどの計算結果の表示

### visual mode 基本

状態

-   `q` normal modeへ移行
-   `:` normal modeの命令受け付け
-   `c` cursor mode (toggle)
    -   less と vi の切り替え的な
-   `p` rotate print mode (toggle)
    -   disasm mode が一番使いやすい気がする
-   `V` call graph表示
    -   事前に`aaaa`とかが必要

移動

-  `h` `j` `k` `l` 移動 -  `>` `<` 多めに進む/戻る
    -   `C-f` `C-b` とか `SPACE` `b` に当ててほしかったような
-  `1` $\dots$ `9` jump
-  `u` / `U` jumpのundo/redo
-  `_` HUDがでてきてsymbol名を絞り込んでjump
    -   comment / flag も対象
    -   画面上に表示されている文字列全体からの検索とかではない

注釈

-   `;` comment (命令などの右側に`; foo bar`と書かれるやつ)
    -   `-` と入力すると削除
    -   環境に依るだろうが日本語はだめ [#2032](https://github.com/radare/radare2/issues/2032)
-   `f` flag (機械語とかと同じ深さで `;-- main: ` みたいになるやつ)
    -   `-` と入力すると削除
    -   区間に対して注釈付けたいが見付からない indentがしたい
-   `dr` `dn` 命名
    -   関数名やlocal変数名を変えれる `local_10h` みたいなあれ
    -   命名対象はcursorの位置で指定する x座標にも影響受けるので注意


### 状態保存 project機能

何もしなければ終了時に解析情報やコメントなどのradare2の状態は全て破棄される。
これを回避するにはproject機能を使う。

`$ r2 -p ${PROJECT_NAME}` で起動するとprojectを開きつつ起動。
projectがなければ新規作成される。
`$ r2 -p ${PROJECT_NAME} ${FILE}` としてもfileは無視されるので、新規作成後は`:o ${FILE}`で陽に開く。
projectが開かれていれば終了時に `Do you want to save the 'foo' project? (Y/n)` などと聞いてくれるのでここで状態が保存される。

### 書き込み

開いているfileへの書き込みも可能。
defaultでは読み込み専用なので、まず `:oo+` commandで書き込み可能にする。
あとはvisual modeのcursorで書き込み位置を指定し`:w foo`とかで書き込み。

書き込み例:

-   `:w \x90\x90\x90\x90` $4$byte分を `nop`で埋める
-   `:wa xor eax, eax` 対応する機械語を書き込み (この場合 `\x31\xc0`)
-   `:wen 3` $3$byte挿入 `\0`埋め
    -   `:r+3` でもだいたい同じ
-   `:r-3` $3$byte削除
    -   `:r 3` はfile全体を$3$byteに切り詰めなので注意

実行すれば即座に実fileに反映されることには注意。
write cacheみたいな機能は存在するがdefaultで無効、backup取った方が早い。

### debugger

機能的にはgdb-pedaと張り合えるぐらいのdebugger modeがある。
安定性や信頼性はちょっと怪しい気がする。
`$ r2 -d ${FILE}` でdebugger modeで起動。

-   `:V!` / visual mode `!` でpanel表示
    -   gdb-pedaのprompt相当
    -   `$ r2 -dcV! ${FILE}` で起動してもよい
-   `:ds` / visual mode `s` step実行
    -   gdbの`si`
    -   `:ds 100` または `:100ds` で $100$回
-   `:dso` / visual mode `S` step over実行
    -   gdbの`ni`
    -   visual modeのままだと標準入出力がだめな感じになる つらい
-   `:db sym.main` breakpoint設置
    -   visual modeなら `B` でcursor位置に設置/除去
-   `:dc` 実行再開
    -   gdbの`continue`
-   `:dcr` その関数を抜けるまで実行
    -   `:dsf` もだいたい同じ
-   `:dcu sym.main` main関数まで実行
    -   `:dsu sym.main` もだいたい同じ
-   `:dbt` backtrace表示
-   `:dm` `/proc/$PID/maps`と同じ情報表示
    -   gdb-pedaの`vmmap`
-   `:pxr @ ${ADDR}` メモリ上をいい感じに表示
    -   `:pxr @ rsp`が便利
    -   gdb-pedaの`telescope`

### 情報源

-   <https://github.com/radare/radare2>
-   [Radare2 Book](https://radare.gitbooks.io/radare2book/)
