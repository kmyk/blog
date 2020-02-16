---
category: blog
layout: post
date: "2016-12-02T21:13:22+09:00"
tags: [ "ctf" ]
---

# CTFの紹介と始め方

アクセス解析を見ると過去に書いた記事がとても人気である。
CTF 入門 初心者 始め方 といった記事が望まれているのだと思う。しかしあの記事はまだ私が始めて間もない時のものなので新たに書いた。

## CTFとは

Capture The Flagの略で、計算機を用いた競技のひとつ。
何らかの方法で隠された文字列(flagと呼ぶ)を見付け出し提出すると得点となる。
セキュリティ系が元であるので、例えばプログラムの脆弱性を突いて鯖に侵入しflagを奪取する、流出したデータを解析しflagを見付け出す、といった想定の問題が多い。
「ハッキングコンテスト」みたいな雑な紹介をされることがよくある。

CTFは出題範囲がかなり広く、このため一般的なCTFでは問題がジャンル分けされていることが多い。
主なジャンルとしては pwn, crypto, reversing, web がある。

-   PWN
    -   プログラムの脆弱性を突く問題
    -   鯖上のプログラムのbuffer overflowのバグを起点にstackを書き換え`/bin/sh`を実行とかそういうの
-   Crypto
    -   暗号の問題
    -   この部分で素数$p$の選び方がまずいので離散対数問題が現実的な時間で解けて暗号文がどうこうみたいなやつ
-   Reversing
    -   バイナリを解析する問題
    -   例えば、アセンブリを頑張って読んで把握しSATソルバ等に渡してflagにする
-   web
    -   webの問題
    -   SQL injectionやXSS等をする
-   PPC (Professional Programming and Coding)
    -   競技プログラミングっぽい問題
-   Forensic, Steganography, Network
    -   頑張ってデータを抜き出す問題
-   misc (Miscellaneous)
    -   その他の問題

たいていのイベント型のCTFはチーム戦である。
幅広いジャンルを扱うので分野ごとに分担することになる。
ひとりのみからなるチームで出ても問題はない。
一方で$1$チームからの出場人数に上限がないことは多く、初心者であってもチームにいて特に不利益はないので、やる気のある人間が参加したいと言えば受け入れてくれるチームは多いだろう[^1]。

## 参加方法

### 常設CTF

期間制限なく公開されている問題を解き順位を競う形のCTF。
基本的に解法の公開は歓迎されない。そのため勉強するには不向き。

とりあえず問題を見てみるとよい。

-   [ksnctf](http://ksnctf.sweetduet.info/)
-   [CpawCTF](http://www.cpaw.site/)

### イベント型CTF

$2$日間等の期間を決めて行われるCTF。
たいてい有力チーム等が各々勝手に開催する。
終了後は参加者が解法を公開し、また問題ファイル等も公開される。

開催情報はCTFtimeというサイトにまとめられている。
ひとりでもいいのでとりあえず参加してみるとよい。

-   <https://ctftime.org/>

## 資料

### 本

とりあえず始めるには以下の$2$冊がおすすめ。
攻略本というよりルールの説明書。
ある程度慣れれば不要になるだろうがある程度慣れるまでが一番大変なので、周りに丁寧に教えてくれる上級者がいないなら持っておくとよい。

-   [セキュリティコンテストチャレンジブック -CTFで学ぼう! 情報を守るための戦い方](http://www.amazon.co.jp/dp/4839956480)
-   [Hacking: 美しき策謀 第2版 ―脆弱性攻撃の理論と実際](http://www.amazon.co.jp/dp/4873115140)

### Challenges Lists

先人らがまとめた良問集。
やる問題に困ったら上から順に解くとよい。

-   [Pwn Challenges List](http://pastebin.com/uyifxgPu) by [bata](https://twitter.com/bata_24)
-   [Crypto Challenges List (2015)](http://pastebin.com/cSfZW2yX) by [Shiho Midorikawa](https://twitter.com/elliptic_shiho)
-   [Crypto Challenges List (2016)](http://pastebin.com/28SrvQ9b) by [Shiho Midorikawa](https://twitter.com/elliptic_shiho)
-   [Reversing Challenges List](http://pastebin.com/q7LGi8w5) by [ふるかわ](https://twitter.com/_N4NU_)
-   [Web Challenges List 2016](http://pastebin.com/6EH6X0yL) by [193s](https://twitter.com/_193s)

リスト埋めを管理するページも存在する: [ctf4u](http://ctf.katsudon.org/ctf4u/)

### 過去問

イベント型のCTFの過去問はまとめられていて、たいてい問題名で検索すれば出てくる。
あまり古い問題は環境が変わって動かないことも多いので注意。

-   [github.com/ctfs](https://github.com/ctfs)
-   [captf.com](http://captf.com/)


## 関連イベント

### katagaitai勉強会

katagaitaiというチームが主催する勉強会。
関東/関西の$2$箇所でやってくれる。
懇親会みたいなのは付いてないのでそういうのが苦手な人でも安心。
資料はまとめて公開されていて単体でもかなり役に立つ。

-   [katagaitai CTF勉強会 過去資料 pwnables](http://www.slideshare.net/bata_24/presentations) by [bata](https://twitter.com/bata_24)
-   [katagaitai CTF勉強会 過去資料 Crypto](http://www.slideshare.net/trmr105/presentations) by [trmr](https://twitter.com/trmr105)

### セキュリティ・キャンプ

-   <http://www.security-camp.org/>
-   <https://twitter.com/security_camp>

合宿形式の勉強会。
年齢制限/選考があるがその分豪華だった。
地方大会というのもあるらしい。

### SECCON

-   <http://2016.seccon.jp/>

CTFっぽいなにか。地方大会と称して各地で開かれる予選とオンラインでやる本予選がある。
同じ所がCTF for ビギナーズ、CTF for GIRLS等といったイベントもやっているらしい。

## 勉強方法等

基本的とりあえず過去問。$30$分から$1$時間ほど調べて/考えてみてまったく進展がない/何をすればいいか分からないなら解説を見るべき。ただしその後手を動かすこと。

### PWN

最初の壁が厚い。
簡単な問題でも、始めてやる際には難しく感じる人は多い。

まずは[村人A](http://ksnctf.sweetduet.info/problem/4)と[村人B](http://ksnctf.sweetduet.info/problem/23)を解きたい。
零から自力で解くのは無理があるため、ほとんど答えが[セキュリティコンテストチャレンジブック](http://www.amazon.co.jp/dp/4839956480)に書いてあるのでこれを読む。
村人ふたりを倒すまでがチュートリアルという感はあるが、一方で場合によっては数週間かかったりするのでゆっくり頑張って。
あとは[Pwn Challenges List](http://pastebin.com/uyifxgPu)を好きに埋めていけばよい。

[ももいろテクノロジー](http://inaz2.hatenablog.com/)(特に[category/Exploit](http://inaz2.hatenablog.com/archive/category/Exploit))は色々載っているので眺めておくべき。
道具はobjdump(あるいはradare2やIDA)にgdb + [gdb-peda](https://github.com/longld/peda)と[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)とがあればよい。
言語の周りはPython + [pwntools](https://github.com/Gallopsled/pwntools)がおすすめ。

### Crypto

とりあえずは[Crypto Challenges List](http://pastebin.com/cSfZW2yX)を上から解いていきたい。
体系的にやりたいなら[₍₍ (ง ˘ω˘ )ว ⁾⁾ < 暗号楽しいです](http://elliptic-shiho.hatenablog.com/)の参考文献を辿ればよさそう。競プロとも近い。

たいていはPythonで済むが、たまにC++が欲しくなるので使えるとよい。
[pycrypto](https://pypi.python.org/pypi/pycrypto)と[gmpy2](https://pypi.python.org/pypi/gmpy2)はimportしておこう。
たまに[pwntools](https://github.com/Gallopsled/pwntools)も使いたくなる。

### Reversing

pwnしてれば自然とある程度できるようになるはず。

### Web

勉強するに難しいジャンル。開催されるCTFに積極的に参加していく他ないはず(よく知らず)。
過去問は問題サーバーが落ちているため試すのが難しく、一方で常設問は解説がないためたいてい既に解ける問題しか解けないため厳しい。

知識もかなり色々要求される。

### PPC

[競](https://atcoder.jp/)[プ](http://yukicoder.me/)[ロ](http://judge.u-aizu.ac.jp/onlinejudge/)して。

---

# CTFの紹介と始め方

この記事は[CTF Advent Calendar 2016](http://www.adventar.org/calendars/1714)の$2$日目の記事です。
昨日はakiymさんの[まずはCTFの過去問を解く](http://akiym.hateblo.jp/entry/2016/12/01/235939)、明日はBo Wangさんです。

[^1]: 弊チーム(ゆるふわ)はCTFをやりたい人は(まったくの初心者でも)歓迎します。興味のある人は適当に連絡してください。
