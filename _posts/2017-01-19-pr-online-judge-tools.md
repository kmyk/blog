---
category: blog
layout: post
date: "2017-01-19T06:48:06+09:00"
edited: "2018-09-26T05:12:47+09:00"
title: "競技プログラミングのための補助ツールを作った"
tags: [ "competitive" ]
---

URL: <https://github.com/kmyk/online-judge-tools>

この記事の記述時のversionは0.1.9です。
<font color="red">この記事の内容はすでに古くなっています。プロジェクト内の公式なドキュメント <a href="https://online-judge-tools.readthedocs.io/en/master/introduction.ja.html">https://online-judge-tools.readthedocs.io/en/master/introduction.ja.html</a> を利用してください。 (15 秒後に自動でリダイレクトされます)</font>
<script>
setTimeout(function () {
    location.href = "https://online-judge-tools.readthedocs.io/en/master/introduction.ja.html";
}, 15 * 1000);
</script>

## 概要

競プロの際の典型作業を自動化するためのツールです。

主な機能としては以下があります。

-   サンプルケースの自動取得
-   取得したケースに対するテスト
-   回答の提出

また、以下のような機能も持ちます。

-   問題文中の入力フォーマットを解析し、入力取得コードを自動生成
-   入力ケースと愚直解を与え、これを想定解として出力ケースを生成
-   複数ケースを含む入力ファイルを解析し、個別ケースを切り出し
-   標準入出力で受け答えするジャッジプログラムを用いる、リアクティブ問のテスト

特徴として、

-   導入が楽
-   高精度

## 導入

pythonのpackageとしても公開してある<sup>[[link]](https://pypi.python.org/pypi/online-judge-tools)</sup>ので、導入は以下の$1$行だけで完了します。

``` sh
$ sudo pip3 install online-judge-tools
```

更新の取得は以下です。

``` sh
$ sudo pip3 install --upgrade online-judge-tools
```

Windows上では Windows Subsystem for Linux で動くという報告を見ました。

## 利用

### download

サンプルケースの自動取得は以下のようにURLを指定して実行すればできます。
ちゃんとテストも書いて丁寧に実装しているので精度は高いはずです。

``` sh
$ oj dl URL
```

多めに出力が出ます。サンプルケースの内容も表示されるので、何かまずそうならすぐ気付けるようになっています。terminal上だと色が付いたり太字になったりします。

``` sh
$ oj dl https://beta.atcoder.jp/contests/agc001/tasks/agc001_a
[x] problem recognized: <onlinejudge.atcoder.AtCoderProblem object at 0x7f1fb6c4dd30>: https://beta.atcoder.jp/contests/agc001/tasks/agc001_a
[*] load cookie from: /home/user/.local/share/onlinejudge/cookie.jar
[x] GET: https://beta.atcoder.jp/contests/agc001/tasks/agc001_a
[x] 200 OK
[*] skipped due to language: current one is lang-ja, not lang-en: Sample Input 1 
[*] skipped due to language: current one is lang-ja, not lang-en: Sample Output 1 
[*] skipped due to language: current one is lang-ja, not lang-en: Sample Input 2 
[*] skipped due to language: current one is lang-ja, not lang-en: Sample Output 2 
[*] save cookie to: /home/user/.local/share/onlinejudge/cookie.jar

[*] sample 0
[x] input: 入力例 1
2
1 3 1 2
[+] saved to: test/sample-1.in
[x] output: 出力例 1
3
[+] saved to: test/sample-1.out

[*] sample 1
[x] input: 入力例 2
5
100 1 2 3 14 15 58 58 58 29
[+] saved to: test/sample-2.in
[x] output: 出力例 2
135
[+] saved to: test/sample-2.out
```

### test

サンプルケースを用いてテストを行います。コマンドは以下の形で、`-c COMMAND`が省略された場合は`./a.out`が使われます。

``` sh
$ oj test [-c COMMAND]
```

``` sh
$ oj test -c ./a.pl
[*] 2 cases found

[*] sample-1
[x] time: 0.002464 sec
[+] AC

[*] sample-2
[x] time: 0.002267 sec
[-] WA
output:
1


expected:
1
2
Fizz
4
Buzz
Fizz
7
8
Fizz
Buzz
11
Fizz
13
14
FizzBuzz
16


[x] slowest: 0.002464 sec  (for sample-1)
[-] test failed: 1 AC / 2 cases
```

### login

提出やコンテストの本番中の利用にはloginが必要です。コマンドは以下です。

``` sh
$ oj login URL
```

実行するとusername/passwordが聞かれるので入力してください。
loginに成功するとsession情報のみがファイルに保存されます。

``` sh
$ oj login http://codeforces.com
[x] service recognized: <onlinejudge.codeforces.CodeforcesService object at 0x7fd80b96c780>: http://codeforces.com
[*] load cookie from: /home/user/.local/share/onlinejudge/cookie.jar
[x] GET: http://codeforces.com/enter
[x] 200 OK
Username: user
Password: 
[x] POST: http://codeforces.com/enter
[x] 200 OK
[+] Welcome, user.
[*] save cookie to: /home/user/.local/share/onlinejudge/cookie.jar
```

### submit

(この節はversion 0.1.38時に更新されました)

submitもできます。
shellのヒストリ機能で誤爆するとペナルティが生えて危ないので、あまり使わない方がいい気がしています。
なので優先順位が低くあまり対応サービスは多くなく、version 0.1.38時点ではAtCoderとTopCoder Marathon Matchのみです。
機能の性質上、継続的にメンテをしないと勝手に壊れていやすくかつテストもしにくいことも理由です。

``` sh
$ oj submit URL FILE [--language LANG] [--golf]
```

主に拡張子から提出言語を自動で推測してくれますが、不足する場合は `--language` を使って言語を指定してください。

``` sh
$ oj submit http://yukicoder.me/problems/no/9002 a.pl --language perl
[x] problem recognized: <onlinejudge.yukicoder.YukicoderProblem object at 0x7fb2ce08eb38>: http://yukicoder.me/problems/no/9002
[*] code:
#!/usr/bin/perl
print+(Fizz)[$_%3].(Buzz)[$_%5]||$_,$/for 1..<>

[*] load cookie from: /home/user/.local/share/onlinejudge/cookie.jar
[x] GET: https://yukicoder.me/problems/no/9002/submit
[x] 200 OK
[x] POST: https://yukicoder.me/problems/16/submit
[x] 200 OK
[+] success: result: https://yukicoder.me/submissions/144776
[*] save cookie to: /home/user/.local/share/onlinejudge/cookie.jar
```

実用上重要なのはgolfの用途です。
ブラウザ上から提出をすると改行が CRLF になる場合でもこの機能で改行が LF なファイルを提出をすれば CR の分だけ得をします。
必要なら `--golf` オプションを指定すれば、CRLFの置換とファイル末尾の改行の削除をしてから提出してくれます。

Marathon Matchへの提出では提出結果に差はないですが、提出時間制限に引っ掛かたときや夜寝る前に予約投稿ができるという嬉しさがあります。

### generate-scanner

入力フォーマットを解析して入力取るコードを自動生成します。
精度はそれなりなので注意。

例えば、

```
N
L_1 L_2 ... L_2N
```

が、

``` c++
int N; cin >> N;
vector<int> L(2*N); repeat (i,2*N) cin >> L[i];
```

になります。

コマンドは次です。

``` sh
$ oj g/s URL
```

しかしeditorのコマンドに割り当てておくべきです。以下はvimの例。

``` vim
nnoremap <space>gs :r! oj generate-scanner --silent --repeat-macro=repeat 
```

実行例。

```
$ oj generate-scanner --repeat-macro=repeat https://beta.atcoder.jp/contests/agc001/tasks/agc001_a
[!] This feature is experimental.
[x] problem recognized: <onlinejudge.atcoder.AtCoderProblem object at 0x7f1c700c3cf8>: https://beta.atcoder.jp/contests/agc001/tasks/agc001_a
[*] load cookie from: /home/user/.local/share/onlinejudge/cookie.jar
[x] GET: https://beta.atcoder.jp/contests/agc001/tasks/agc001_a
[x] 200 OK
[*] save cookie to: /home/user/.local/share/onlinejudge/cookie.jar
[+] success:
int N; cin >> N;
vector<int> L(2*N); repeat (i,2*N) cin >> L[i];
```

### generate-output

実装と入力ケースから対応する出力ケースを作ります。
yukicoderの作問時の $\dots$を想定解として出力ケースを生成 みたいなやつです。

``` sh
$ oj g/o [-c COMMAND]
```

### split-input

ICPCでよくある単一ファイルに複数ケース入ってる場合に、ケースごとにファイルに切り分けます。
既にある実装を利用し、入力を$1$行ずつ与えて、出力が発生したらケースの区切りが来たと認識して分割します。

``` sh
$ oj s/i [-i SOURCE] [-o DEST_FORMAT] [-c COMMAND]
```

### test-reactive

リアクティブ問のテストを簡単にする機能です。
パイプを作っていい感じに繋ぐ処理をしてくれるので、入出力を標準入出力で行うようなジャッジプログラムを書くだけでよくなります。

``` sh
$ oj t/r [-c COMMAND] JUDGE_COMMAND
```


## 貢献

何か壊れていたら[issue](https://github.com/kmyk/online-judge-tools/issues)とかで教えてください。
特に、コンテスト中に発生すると成績に深刻な影響を与えるバグ(例えば、サンプルケースの取得で一見上手くいってるけど実は失敗している場合など)は、例えばURLを投げ付けてくれるだけでも十分ありがたいです。
ちなみにこうやってわざわざ記事を書いて宣伝しているのは、バグを見つけて報告してくれるユーザを獲得するためです。

pull requestも歓迎します。

## 競合

参考までに

-   [nodchip/OnlineJudgeHelper](https://github.com/nodchip/OnlineJudgeHelper)
    -   作者: [nodchip](https://twitter.com/nodchip)さん
    -   一番有名なやつ
    -   私も以前使っており、何度かpull requestを出した
    -   先発なので精度が良くない
-   [en30/online-judge-helper](https://github.com/en30/online-judge-helper)
    -   作者: [en30](https://twitter.com/en30y)さん
    -   <http://blog.en30.net/2015/05/04/online-judge-helper.html>
    -   使ったことないので分からない
    -   chrome_extension でHTMLを引っ張ってきて解析までするのは筋が良さそう
-   [kyuridenamida/atcoder-tools](https://github.com/kyuridenamida/atcoder-tools)
    -   作者: [kyuridenamida](https://twitter.com/kyuridenamida)さん
    -   入力フォーマット解析からのコード自動生成機能がある
        -   使ったことないけど現在のこれより高精度だと思う
-   AtCoderのA問題を$3$秒でACするやつ: <https://beta.atcoder.jp/contests/arc030/submissions/286413>
    -   作者: [mkotha](https://twitter.com/mkotha)さん

機能があまり被らないもの:

-   主にAtCoderの便利user script群, <https://koyumeishi.github.io/>
    -   作者: [koyumeishi](https://twitter.com/koyumeishi_)さん

---

[^1]: 当初は「あるいは素直に仮想環境を使ってください」と書いていたのですが、「WindowsがいいからWindows使ってんのに、仮想環境を使うのが素直な選択肢なわけねえだろ何いってんだ」という意見があり、それはそうだなと思ったので訂正しました。

---


-   Thu Jan 19 17:11:18 JST 2017
    -   「...素直に仮想環境を...」の文言を修正
-   2018年  8月 27日 月曜日 14:32:41 JST
    -   WSLについて言及
    -   golfやMM用途など提出機能に関して追記 (version 0.1.38)
-   2018年  9月 26日 水曜日 05:12:27 JST
    -   `s/CLRF/CRLF/g`
-   2018年  9月 26日 水曜日 05:18:09 JST
    -   `s/RF/LF/g`
