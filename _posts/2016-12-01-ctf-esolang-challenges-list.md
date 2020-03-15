---
category: blog
layout: post
redirect_from:
    - "/blog/2016/11/30/ctf-esolang-challenges-list/"
date: "2016-12-01T00:40:32+09:00"
tags: [ "ctf", "esolang" ]
---

# CTF Esolang Challenges List (2016)

CTF(capture the flag)をしていて見つけたesolang問を覚えている範囲で全部列挙した。
と言っても出てないCTFは多いので漏れも多いはず。

一番最後のQSetは言語としても問題としても面白いのでお気に入り。

## Hackcon 2016: in-rainbows

<https://github.com/ctfs/write-ups-2016/tree/master/hackcon-ctf-2016/forensic/in-rainbows-150>

画像が与えられるのでバケツ塗り潰しすると何か浮かび上がってくる問題。
出てきたのがbrainfuckのコードだった。

## Qiwi Infosec CTF 2016: PPC 300_2

brainfuckのコードを出力するbrainfuckのコードを出力する $\dots$ brainfuckのコードが与えられるので実行する問題。
特に処理系の最適化とかは不要だった。

## TUM CTF 2016: boot2brainfuck

<https://github.com/ctfs/write-ups-2016/tree/master/tum-ctf-2016/pwn/boot-2-brainfuck-150>

$16$bit環境のbrainfuck処理系で、領域外に機械語を書き込んでファイルを読み出す。
brainfuck部分は機械語を固定文字列として出力するだけだった。

## Internetwache CTF 2016: Eso Tape

<https://github.com/ctfs/write-ups-2016/tree/master/internetwache-ctf-2016/reversing/eso-tape-80>

妙な文字列が飛んでくるからどうにかして、という問題。
その文字列は見た目が変なタイプのesolangのコードだった。

曰く、<http://esolang.org>の[Hello world一覧](http://esolangs.org/wiki/Hello_world_program_in_esoteric_languages)を検索すれば見つかった。

## Tokyo Westerns/MMA CTF 2nd 2016: whiteout-mathmatics-200

<https://github.com/ctfs/write-ups-2016/tree/master/mma-ctf-2nd-2016/reverse/whiteout-mathmatics-200>

whitespaceのコードを解析するrevの問題。whitespace自体が比較的高級なので読んで競プロに落とすだけだが、悪い問題ではない。

## Tokyo Westerns/MMA CTF 2nd 2016: Interpreter

<https://github.com/ctfs/write-ups-2016/tree/master/mma-ctf-2nd-2016/pwn/interpreter-200>

befunge interpreterにソースコードを食わせて`/bin/sh`を起動するpwnの問題。どこがすごいというわけでもないが、良い問題ではある。

空間が固定長配列で取ってあるので領域外参照で適当にすればよい。
befungeには詳しくないので知らないが、brainfuckでは現実によくある脆弱性。

ついでに、同twctfで出たruby golf/trivia問の[Private / Local / Comment](https://github.com/ctfs/write-ups-2016/tree/master/mma-ctf-2nd-2016/ppc/private-local-comment-220)もおすすめ。

## HITCON quals CTF 2016: RegExpert, moRE

-   <https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/misc/regexpert-200>
-   <https://github.com/ctfs/write-ups-2016/tree/master/hitcon-ctf-2016/misc/more-350>

正規表現で$a^nb^n$や$a^nb^nc^n$にmatchさせたりする問題。田中哲スペシャルという魔法があるので(正規表現であるにも関わらず)できる。面白い。

これに刺激を受けてshinhさんが[Brainfuck interpreter in Ruby&#39;s Regexp - 兼雑記](http://shinh.hatenablog.com/entry/2016/10/17/024329)を作っていた。

## ABCTF 2016: QSet 1, QSet 2, QSet 3

-   <https://github.com/ctfs/write-ups-2016/tree/master/abctf-2016/ppc/qset1-100>
-   <https://github.com/ctfs/write-ups-2016/tree/master/abctf-2016/ppc/qset2-150>
-   <https://github.com/ctfs/write-ups-2016/tree/master/abctf-2016/ppc/qset3-200>

記号の多重集合を命令や状態とする(おそらく)独自言語でのppc問。それぞれ$\lambda n. 2n$, $\lambda n. \sqrt{n}$, $\lambda p q e. e^{-1} \pmod{(p-1)(q-1)}$(RSA秘密鍵)をする問題で、最後は頑張って最適化する必要がある。とても良い問題。

### 概要

十分に面白いので丁寧に書いておく。spoilerなので注意。

まず言語仕様について。
syntaxは重要でないのでsemanticsのみ示す。
$\newcommand{\llbrace}{\{\!\{}$
$\newcommand{\rrbrace}{\}\!\}}$
プログラムは多重集合の対の列 $F = ( (x_0, y_0), (x_1, y_1), \dots, (x\_{n-1}, y\_{n-1}) )$である。
状態として多重集合$s$を持つ仮想機械がこれに従い動く。
実行は以下を繰り返す:

-   $i = \min \\{ i \mid x_i \subset s \\}$が存在すれば、$s \gets s \setminus x_i \cup y_i$とする
-   存在しなければ、停止する

入出力は非負整数列として行われる。
入力が$( x_0, x_1, \dots, x\_{n-1} )$であるとき、仮想機械の初期状態を$\llbrace \underbrace{i_0, i_0, \dots i_0}\_{x_0}, \underbrace{i_1, i_1, \dots i_1}\_{x_1}, \dots, \underbrace{i\_{n-1}, i\_{n-1}, \dots i\_{n-1}}\_{x\_{n-1}} \\rrbrace$とし、出力が$( y_0, y_1, \dots, y\_{m-1} )$であるとき、停止時の状態を$\llbrace \underbrace{o_0, o_0, \dots o_0}\_{y_0}, \underbrace{o_1, o_1, \dots o_1}\_{y_1}, \dots, \underbrace{o\_{n-1}, o\_{n-1}, \dots o\_{n-1}}\_{y\_{n-1}} \\rrbrace$として表現する。

つまりはregister machineである。
単なる$2$-counter machineでもTuring完全というのは知られているので、この言語も明らかにそうである。

問題の実装には、instruction pointerの値を示す記号群と、その他のdataを表すための記号を区別すると見通しがよい。
再帰関数を書くには向かないのでloopに展開したい。
とはいえ自由に名前を付けられるので、手書きであっても比較的書きやすい言語である。

最適化に関して。
愚直な実装では鯖でのstep数制限、あるいはコード長制限に引っ掛かるだろう。
これは以下の$2$点を行えば解決する:

-   ボトルネックになっている置換$( x_i, y_i )$の前に$( \underbrace{x_i \cup x_i \cup \dots x_i}\_{n}, \underbrace{y_i \cup y_i \cup \dots y_i}\_{n} )$に追加する (その部分の速度が$n$倍になる)
-   コード中の記号をすべて$1,2$文字のものに置き換え、空白の削除等をする (上の定数倍高速化はコード長を増大させるので必要)

ここまで考慮して実装(を出力するプログラムを実装)すれば$1, 2, 3$全てのflagが得られる。

---

# CTF Esolang Challenges List (2016)

この記事は[Esolang(難解プログラミング言語) Advent Calendar 2016](http://qiita.com/advent-calendar/2016/esolang)の$1$日目です。
次はiroriさんの UnlambdaでVMを実装する（前編） です。
