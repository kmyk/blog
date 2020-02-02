---
category: blog
layout: post
title: "セキュキャン2016応募用紙その他まとめ"
date: 2016-06-16T00:55:35+09:00
tags: [ "seccamp", "security-camp" ]
---

通りました。
どこを評価されて通ったのかは分かりません。
落としてきやがったら行ってやらねぇからな、ぐらいの気持ちでいたのですが、やはり通ると嬉しいものですね。
せっかくなので忘れないうちに反省会をしておこうかなと思ったのでまとめました。
しかしするのが遅かったためか他人の応募用紙や出題者の言明があまり見つからず、他人の応募用紙は文章量があって読むのがつらかったので、実質なにもしていない気もします。

## 感想

### 共通問題

私の守備範囲に異様な偏りが見られて困った。
この部分が評価されて通ったのだったらなんだか嬉しいなと思う。

### 選択問題 1

なんだかすごく標準的な雰囲気がある問題。
どんなことをどこまで書けるのかよく分からないのでちょっと困る。

64bit ASLR PIEぐらい書けばいいかなと思ってたけど、mallocの種類の話は忘れていた(ちょっと考えたけど、面倒だったしすぐやめた記憶がある)。

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">問1はASLRの他に、PIE, mallocの実装の種類（glibcのdlmallocとか、Googleが作ったtcmallocとか、mallocにもいろいろある）、mmapの実装とかの方面に話を発展できるかなーと思った</p>&mdash; しゃろ (@Charo_IT) <a href="https://twitter.com/Charo_IT/status/742921810467913730">June 15, 2016</a></blockquote> <script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

### 選択問題 4

何をさせたいのかあまり理解できなかった問題。
問題文がごちうさとか言っててなんだか適当さを感じたのもあって問題文の不備は適当に推測して適当にした(うだうだ指摘することもないかなと思って特に書かなかった)し、計測がどうこうとあったのでそういうところを見たいのかなと思った(でも面倒だったので`std::string`でえいってした)。全体的にはずしている感じがある。
たしかにプロトコルの解釈の差は脆弱性に繋がるだろうし、実際そこは気付いていなかったので勉強になった。

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">そうそう課題4については、<br>1. ポインタをちゃんと扱えるか<br>2. エラー処理ちゃんとしているか<br>3. メモリリークしてないか<br>4. 移植性（エンディアン）について、特に組込系ですって人がちゃんと気にしてるか<br>（続く）</p>&mdash; CHUBACHI, Yosuke (@ybachi) <a href="https://twitter.com/ybachi/status/739016253071708160">June 4, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">という基本的なところに加えて、<br>Adv. 1. プロトコルに解釈の余地があるが、その実装にコメントがあるか<br>Adv. 2. マッチング処理の最適化（ルールの適用順によっては、ループ回数が減らせるか、とか）<br>あたりを評価できるように課題を作ってます。</p>&mdash; CHUBACHI, Yosuke (@ybachi) <a href="https://twitter.com/ybachi/status/739017402189369344">June 4, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">解答は解釈部分によって変わるようにわざとしている（競プロじゃないからね）んで、解答の正誤は特に関係ないっす。結構たくさんの人がこころぴょんぴょんしてくれたみたいで、よかった。</p>&mdash; CHUBACHI, Yosuke (@ybachi) <a href="https://twitter.com/ybachi/status/739018273711218688">June 4, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">せやかて、プロトコルに解釈の余地があったらおかしいやろ！っていう話もあるんだけど、ネットワークプロトコルの実装には結構そういう脆弱性があったり、相互接続性がおかしい、みたいなこともあるんで、その辺りちょっと考えるキッカケになったら嬉しいですね。</p>&mdash; CHUBACHI, Yosuke (@ybachi) <a href="https://twitter.com/ybachi/status/739019047812009984">June 4, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

### 選択問題 8

qiraで見るだけだった。でも一番好きです。ROPはいいぞ。

継続っぽい話をしたが、ROPへの対策機構の話をするという手もあったらしい。

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">問8はROPそのものの話に加えて、EMETのROP対策の話もできるかなーと</p>&mdash; しゃろ (@Charo_IT) <a href="https://twitter.com/Charo_IT/status/742923408539713536">June 15, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

### 選択問題 10

これも楽しかった。
そういうのがあるのは知っていたがそれ以上は知らなかったので勉強になった。
問題文から対象となる環境が推測できる。

応募用紙には書かなかったが、vmware内で

``` sh
$ cat /dev/port
```

ってしたら仮想環境が終了するのとかすごくよかった。

## 他の人の応募用紙

眺めているとどれも文章量があって、これが「熱意」ってやつなのかあという気持ちになる。
<del>でも個人的には簡潔に要点だけまとめる方が好きです。</del>

### AC

-   <http://encry1024.hatenablog.com/entry/2016/06/14/232845>
-   <http://yamaguchi-1024.hatenablog.com/entry/2016/06/14/135833>
-   <http://happynote3966.hatenadiary.com/entry/2016/06/15/001412>
-   <http://nonkuru.hateblo.jp/entry/2016/06/12/115416>, <http://nonkuru.hateblo.jp/entry/2016/06/12/122555>
-   <http://damember.sakura.ne.jp/wp/2016/06/01/%E3%82%BB%E3%82%AD%E3%83%A5%E3%82%AD%E3%83%A3%E3%83%B32016%E5%BF%9C%E5%8B%9F%E7%94%A8%E7%B4%99%E3%81%AE%E9%81%B8%E6%8A%9E%E5%95%8F%E9%A1%8C/>
-   <http://titech-ssr.blog.jp/archives/1058074153.html>
-   <http://akkkix.hatenablog.com/entry/2016/06/16/154731>
-   <http://lv7777.hatenablog.com/entry/2016/06/15/005546>
-   <http://tukejonny-programming.hatenablog.com/entry/2016/06/16/%E3%82%BB%E3%82%AD%E3%83%A5%E3%82%AD%E3%83%A3%E3%83%B3%E3%81%AE%E5%BF%9C%E5%8B%9F%E7%94%A8%E7%B4%99>

### 祈られ

-   <http://atofaer.hatenablog.jp/entry/2016/06/14/011354>

落ちたから消した人とか通ってから公開した人が多そう。
しかし、こういう文章にしてもソースコードにしても、恥ずかしいとか言ってないでどんどん公開していく方がいいと思います。

## 他 諸々の呟き

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">セキュキャン受かった方、おめでとうございます。 リスト作ったので登録されてないよ〜って方教えてください <a href="https://t.co/dTw6BTPMYe">https://t.co/dTw6BTPMYe</a> <a href="https://twitter.com/hashtag/seccamp?src=hash">#seccamp</a></p>&mdash; るくす (@RKX1209) <a href="https://twitter.com/RKX1209/status/742554770443894784">June 14, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">セキュキャンの用紙が正確性より熱意重視なのはそうだと思うけど、キャンプ参加後圧倒的に伸びるのは熱意持ってる人だと思う(主観)ので、判断基準は割と間違ってないと思う。</p>&mdash; るくす (@RKX1209) <a href="https://twitter.com/RKX1209/status/742916989434241025">June 15, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">僕はセキュキャン参加当時(2年前？)はアセンブラ読めないし、libcって何？みたいな状態だったけど熱意で押したな なので熱意優先だと思いますよ</p>&mdash; るくす (@RKX1209) <a href="https://twitter.com/RKX1209/status/742594407606554624">June 14, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">セキュキャン選考、あくまでセキュリティ人材の目を新たに探すことが目的で、セキュリティに多少詳しいけど熱意が弱い人より、セキュリティ分からないけど頑張って勉強します&gt;&lt;の方が通りやすいイメージ</p>&mdash; TASUTEN (@tasuten) <a href="https://twitter.com/tasuten/status/742592118904868865">June 14, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">セキュキャンの応募用紙を読んでいると、結構えええ、っていう間違いをしていても通ってる。たぶん、正しさよりもやる気とか手を動かしたかとかを見てるんだろね。</p>&mdash; 僕はbenign (@noritama_ususio) <a href="https://twitter.com/noritama_ususio/status/742914470385569793">June 15, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">残念ながらセキュリティキャンプに落ちてしまった人、申し訳ねぇ申し訳ねぇ。もし悔しい！気持ちがあれば、それをSECCON然り、CTF然り、参加者よりやるじゃんって講師や参加者を見返せるように、これからもっと圧倒的成長して是非我々を見返してくれ！</p>&mdash; CHUBACHI, Yosuke (@ybachi) <a href="https://twitter.com/ybachi/status/742592254070558721">June 14, 2016</a></blockquote><script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

---

## 応募用紙

私のそれ。gistにも上げたやつですが、ここにも載せておきます。

## 共通問題.1

### あなたが今まで作ってきたものにはどのようなものがありますか？ いくつでもいいので、ありったけ自慢してください。

いくつでもよいということなので、過去に製作したものを列挙します。

-   CTFの問題 1問
    -   <http://153.126.150.208/welcome-ctf-2016/>
    -   Blind SQL Injectionを用いた簡単な問題です
-   競技プログラミングやCTFの問題に対する解説
    -   <http://solorab.net/blog/categories/writeup/>
    -   解いた問題に関して情報を残すのは後から参入する人の役に立ち、自分自身にも有益です
-   大学の休講情報を取得するbot
    -   <https://github.com/kmyk/ku-kyuko>
    -   大学が与えてきた確認手段が非常に不便だったのでしかたなく作りました。pythonで簡単にscrapingをしメールで通知させています
-   Forth言語からbrainfuckへの変換器
    -   <https://github.com/kmyk/forth-to-brainfuck>
-   Brainfuck処理系からshellを実行する手法
    -   <http://solorab.net/blog/2016/04/01/bash-on-brainfuck-on-anarchy-golf/>
    -   境界処理のない処理系の上で内側からROPをするものです
-   Brainfuckやsedによるcode golf
    -   <http://solorab.net/blog/2016/03/20/anagol-1st-2nd-3rd-4th/>
    -   <http://solorab.net/blog/2016/03/31/anagol-left-pad/>
    -   Brainfuckとsedは、書くのが非常に楽しいプログラミング言語です

-   Vimのpluginいくつか
    -   CPLというプログラミング言語のハイライト: <https://github.com/kmyk/cpl.vim>
    -   SDLの関数に色を付けるplugin: <https://github.com/kmyk/sdl2.vim>
    -   brainfuckを実行結果を動的に表示するプラグイン: <https://github.com/kmyk/brainfuck-debugger.vim>
    -   brainfuckのまともなハイライト: <https://github.com/kmyk/brainfuck-highlight.vim>
-   Brainfuckの処理系の処理系依存な部分の実装がどうなっているかを自動で判別するツール
    -   <https://github.com/kmyk/brainfuck-interpreter-analyzer>
-   Whitespace言語からアセンブリ言語風疑似言語への変換器
    -   <https://github.com/kmyk/whitespace-translater>
-   オンラインコンパイラ上でサポートされてない言語を使うための簡単なツール
    -   <https://github.com/kmyk/wrap-befunge>
    -   <https://github.com/kmyk/wrap-brainfuck>
-   任意精度の整数演算をするプログラム
    -   <https://github.com/kmyk/arbitrary-precision-arithmetic>
-   JavaScriptによる簡単なゲーム
    -   <https://github.com/kmyk/boxkjs>
    -   <https://github.com/kmyk/singlepong>
-   単純なGCを持つLazy Kインタープリター
    -   <http://solorab.net/blog/2015/12/05/write-tiny-gc/>
-   x86によるlifegame
    -   <http://solorab.net/blog/2016/01/07/lifegame-in-assembly/>
-   CPL言語での簡単なプログラム
    -   <http://solorab.net/blog/2015/06/12/ackermann-function-in-cpl/>
-   Lazy KでのQuine
    -   <http://solorab.net/blog/2014/04/17/quine-in-lazy-k/>
-   Python onelinerによるbrainfuck処理系
    -   <http://solorab.net/blog/2015/02/24/write-brainfuck-in-python-one-liner/>
-   BrainfuckによるQuine
    -   <http://solorab.net/blog/2014/04/27/quine-in-brainfuck/>
-   Grass言語によるFizzBuzz
    -   <http://solorab.net/blog/2015/12/01/fizzbuzz-in-grass/>
-   Brainfuckによる短歌
    -   <http://solorab.net/blog/2015/12/06/brainfuck-tanka/>

### それをどのように作りましたか？ソフトウェアの場合にはどんな言語で作ったのか、どんなライブラリを使ったのかなども教えてください。

特に個人的に気に入っている、Forth言語からBrainfuckへの変換器について話します。
ソースコードは https://github.com/kmyk/forth-to-brainfuck にあります。
作製に用いた言語はHaskellで、依存ライブラリはParsecというパーサコンビネータライブラリのみです。

プログラムの概要や手法を説明します。
プログラムはForth言語の小さなサブセットからBrainfuckへの変換器です。
まずそれぞれの対象言語の特性ですが、Brainfuckは単純なプログラミング言語です。
遷移関数の形に強い制約のあるチューリング機械と思うことができます。
Forthはスタック指向の商用的な使用にも耐える言語です。
Brainfuckは単純な言語ですが、その実質的に半無限のテープの上にスタック構造を作ることは簡単に可能です。
Forth言語のスタック操作命令等は、この上に直接的に写すことができます。
関数定義は直接的な複製で再現し、再帰的な呼び出しは元言語側で展開する約束としました。
最も外側に基本的に停止しないwhile文を置き、そのひとつ内側に巨大なswitchを配置することで、ソフトウェア的にgotoや関数定義を実現することができます。
別の関数を呼び出すときは、継続あるいはリターン先アドレスに相当するものを表現する整数をスタックに積み、呼び出したい関数を指す整数を積み、switchを踏むという形です。
これは機械語の実行の際に行われているものと実質的に同じです。
このようにすることで、Forth言語のプログラムをBrainfuckのプログラムに変換することができます。
このプログラムにより、Brainfuck上で複雑なプログラム(特に計算複雑性の意味で)の記述が容易になります。

### 開発記のブログなどあれば、それも教えてください。コンテストなどに出品したことがあれば、それも教えてください。

諸々の活動に関するblogは http://solorab.net/ です。

作製したプログラムを出品という形で提出したことはありませんが、競技プログラミング等のコンテストへの出場経験はありますので、これについて主要なものを簡単に列挙します。

-   ACM ICPC 2014年 アジア地区予選 出場
-   全国高等専門学校プログラミングコンテスト 第26回 競技部門 4位
-   CODE RUNNER 2015 7位
-   ACM ICPC 2015年 アジア地区予選 27位

## 共通問題．２

### あなたが経験した中で印象に残っている技術的な壁はなんでしょうか？（例えば、C言語プログラムを複数ファイルに分割する方法）

環境構築に関する壁です。
(当時の私の知識では、)Windows上ではいろんな言語やライブラリのコンパイルや使用ができなかったことです。
特に印象に残っている例としては、io languageという言語(http://iolanguage.org/)があります。
この言語の処理系のインストールは ./configure && make && make install を実行するだけでよいと書いてあったにもかかわらず、CygwinやMinGWの上で色々と試しても上手くいかず諦めた記憶があります。

### また、その壁を乗り越えるために取った解決法を具体的に教えてください。（例えば、知人に勧められた「○○」という書籍を読んだ）

Ubuntuを導入しました。
様々な言語やツールやライブラリが、たった4単語入力すれば、待っているだけで自動的にインストールされる様に感動した記憶があります。

### その壁を今経験しているであろう初心者にアドバイスをするとしたら、あなたはどんなアドバイスをしますか？

LinuxやMacを使うよう説得します。
最近のWindows環境はかなり良くなってきているようですが、それでもやはり初心者にはLinuxの方が簡単だと思います。

## 共通問題．３

### あなたが今年のセキュリティ・キャンプで受講したいと思っている講義は何ですか？（複数可） そこで、どのようなことを学びたいですか？なぜそれを学びたいのですか？

特に興味のある講義は次のふたつです。

-   5-D みんなでクールなROPガジェットを探そうぜ
-   67-F なぜマルウェア解析は自動化できないのか

まず5-D ROPの講義についてです。
私はROP (return-oriented programming)が好きです。
ROP chainを組むことはとても楽しいからです。
また、命令に縛りのあるプログラミングという基本的に実用が難しい話題が、自然に現れる制約の元で(攻撃者に、ではあるが)実用されるというのは非常に面白いです。
是非ともクールなROPチェーンを自在に発見できるようになりたいものです。

次に67-F マルウェア解析の講義についてです。
マルウェアそのものに特に強い興味があるというわけではないですが、マルウェア解析のために使われる技術には強い関心があります。
私は頻繁に、Brainfuckやsedのようなあまり可読性が高くはない言語の読み書きをします。
特に、code golfとして複雑に圧縮/最適化されたコードの読み書きをするため、そのデバッグや解析の効率化が課題です。
このような用途に、マルウェア解析に用いられる技術が利用できると考えています。

### あなたがセキュリティ・キャンプでやりたいことは何ですか？身につけたいものは何ですか？（複数可） 自由に答えてください。

3.(1)で述べた理由により、特に以下のような技術に関して詳しい知識を身につけたいです。

-   ROP
-   テイント解析
-   シンボリック実行

加えて、形式的証明に関する技術にも興味があり、これをしたいです。
講義内容の一覧にはこの話題は存在しませんが、何らかの講義の中で触れてもらえると嬉しいです。

また、そのような話題について話ができるような他の参加者と知り合うことができればよいな、とも思っています。


## 選択問題．１

以下は変数hogeとfugaのメモリアドレスを表示するプログラムと、その実行結果です。
実行結果のhogeとfugaのメモリアドレスを見て、思うことを説明してください。
 
・ソースコード

``` c
#include <stdio.h>
#include <stdlib.h>
 
int main(int argc, char **argv){
 int hoge[10];
 int *fuga;
 
 fuga = malloc(1);
 
 printf("hoge address = %p\n", hoge);
 printf("fuga address = %p\n", fuga);
 
 free(fuga);
 return 0;
}
```
 
・実行結果

```
hoge address = 0x7fff539799f0
fuga address = 0x7fca11404c70
```

### 解答

hoge addressとして示された値はスタック領域上のアドレスで、fuga addressとして示された値はヒープ領域上のアドレスです。

まず、64bit環境下で実行されていることが分かります。アドレスが16進12桁であるためです。

次に気になるのは、ヒープ領域のアドレスが大きいことです。
これは、このコードをPIE(position independent executable)としてコンパイルして実行したからだと推測できます。
ヒープ領域はアドレス空間上で、テキスト領域の後ろに配置されます。
PIEでないバイナリであれば大抵テキスト領域は0x400000から始まり、このためヒープ領域が位置するのは0x1ce9000といった比較的小さなアドレスとなります。
一方PIEであれば、実行時にランダムな位置にテキスト領域が配置され、これは例えば0x55f5c8363000のような小さくはないアドレスとなります。
このため、PIEとしてコンパイルされ実行されたと推測できます。

その他の事項として、(ヒープ領域やスタック領域に対する)アドレス空間配置のランダム化(ASLR, address space layout randomization)の影響も受けています。
PIEも含めて、アドレスの配置のランダム化はセキュリティのための機構のひとつで、その内容は名前の通りです。
これにより、攻撃者は攻撃対象のアドレスに仮定を置けなくなります。
たとえばROP(return oriented programming)を行おうとしても、まずテキスト領域がどこに配置されているか知る必要が発生し、攻撃が困難になります。


## 選択問題.4

突然だが、RH Protocolで用いられるRHパケットのフォーマットを以下に示す。なおRH Protocolは実在しないプロトコルであり、その内容について特に意味は無い。

```
Format of RH Packet
|————————|—————...—|———————…—|———————...—|———————...—|
|  Magic (2byte)     | Source(20byte)|Destination(20byte)| Data Length(4byte)| Data( variable )      |
|————————|—————...—|———————…—|———————...—|———————...—|
```

``` c
char Magic [2];
char Source[20]; /* null(‘\0’) terminated ascii strings */
char Destination[20]; /* null(‘\0’) terminated ascii strings*/
uint32_t DataLength; /* min 0, max 4,294,967,295 */
char Data[DataLength]; /* null(‘\0’) terminated ascii strings */
```
 
バイトオーダーはbig endian（network byte order）とする。
 
添付するバイナリは、とあるRHストリームのうち片方向のみを抽出したものである。このバイナリストリームを読み込み、1つのRHパケットが以下の条件のすべてにマッチするときに標準出力に文字列”PASS”、 それ以外の場合は”REJECTED”と表示するCもしくはC++のプログラムを記述し、実行結果と共に提出せよ。また、マッチングにかかるCPUサイクル及びメモリ使用量を計測し記載した場合、評価に加味する。

-   Condition(条件）1: Magicがchar[0] = ‘R’、 char[1] = ‘H’であること。
-   Condition 2: Sourceが”rise-san”または”cocoa-san”であること。なお、”RiSe”や”Cocoa”など、小文字大文字が混ざっていても、マッチさせること。
-   Condition 3: Destinationが”Chino-chan”または”Chino"であること。なお、cond. 2と同じく、小文字大文字が混ざっていても、マッチさせること。
-   Condition 4: Sourceが”cocoa-san”かつDestinationが”Chino”の場合はREJECTする。
-   Condition 5:  Dataに下記の文字列を厳密に含むこと。

``` c
char** valid_order_brand =
{
    “BlueMountain"
    “Columbia”,
    “OriginalBlend"
};
```

-   Condition 6: Dataに下記の文字列を厳密に含まないこと。なお、cond. 4よりも、cond. 5が優先される。

``` c
char** invalid_order_brand =
{
    “DandySoda"
    “FrozenEvergreen”
};
```

### 解答

課題のプログラムを、C++を選択し以下のように実装した。

``` c++
#include <iostream>
#include <string>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

string to_c_str(string s) {
    size_t it = s.find('\0');
    if (it != string::npos) s.erase(it, string::npos);
    return s;
}
bool iequals(string const & s, string const & t) {
    if (s.length() != t.length()) return false;
    repeat (i,s.length()) {
        if (tolower(s[i]) != tolower(t[i])) {
            return false;
        }
    }
    return true;
}

struct rh_packet {
    string magic;
    string source;
    string destination;
    string data;
};
istream & operator >> (istream & in, rh_packet & p) {
    p = {};
    repeat (i,2)  p.magic       += in.get();
    repeat (i,20) p.source      += in.get();
    repeat (i,20) p.destination += in.get();
    uint32_t len = 0;
    repeat (i,4) { // from big endian
        uint8_t c = in.get();
        len = (len << 8) + c;
    }
    if (in) { // skip if it failed to read the length
        repeat (i,len) p.data += in.get();
    }
    if (not in) p = {};
    p.magic       = to_c_str(p.magic); // remove the chars after a null
    p.source      = to_c_str(p.source);
    p.destination = to_c_str(p.destination);
    p.data        = to_c_str(p.data);
    return in;
}

int does_not_satisfy_condition(rh_packet const & p) {
    // condition 1
    if (p.magic != "RH") return 1;
    // condition 2
    if (    not iequals(p.source, "rise-san")
        and not iequals(p.source, "cocoa-san")) return 2;
    // condition 3
    if (    not iequals(p.destination, "Chino-chan")
        and not iequals(p.destination, "Chino")) return 3;
    // condition 4
    if (iequals(p.source, "cocoa-san") and iequals(p.destination, "Chino")) return 4;
    // condition 5
    if (    p.data.find("BlueMountain")  == string::npos
        and p.data.find("Columbia")      == string::npos
        and p.data.find("OriginalBlend") == string::npos) return 5;
    // condition 6
    if (   p.data.find("DandySoda")       != string::npos
        or p.data.find("FrozenEvergreen") != string::npos) return 6;
    return 0;
}

uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

int main() {
    while (true) {
        rh_packet p; cin >> p;
        if (not cin) break;
        uint64_t start, end;
        int q;
        start = rdtsc();
        q = does_not_satisfy_condition(p);
        end = rdtsc();
        // cerr << p.magic << '\t' << p.source << '\t' << p.destination << '\t' << p.data << endl;
        cout << (not q ? "PASS" : "REJECTED") << endl;
        cerr << (end - start) << " cycles";
        if (q) cerr << " (condition " << q << ")";
        cerr << endl;
    }
    return 0;
}
```

上記のプログラムを、

``` sh
$ g++ -std=c++11 a.cpp
```

として手元の環境(Ubuntu 16.04 LTS, x86_64)でコンパイルし、指定された入力に対し実行しました。
このとき標準出力、標準エラー出力は以下のようになりました。
標準エラー出力には、rdtsc命令(read time stamp counter)で計測したCPUクロックサイクル数と、マッチングに失敗した場合はその根拠となる条件の番号を出力させました。

```
PASS
PASS
REJECTED
PASS
REJECTED
PASS
PASS
REJECTED
PASS
REJECTED
PASS
REJECTED
PASS
REJECTED
REJECTED
PASS
REJECTED
PASS
REJECTED
REJECTED
REJECTED
PASS
REJECTED
PASS
REJECTED
REJECTED
REJECTED
REJECTED
PASS
REJECTED
PASS
REJECTED
REJECTED
REJECTED
REJECTED
REJECTED
PASS
REJECTED
PASS
REJECTED
REJECTED
REJECTED
REJECTED
REJECTED
REJECTED
```

```
30020 cycles
3378 cycles
2931 cycles (condition 4)
2593 cycles
2903 cycles (condition 4)
4521 cycles
3265 cycles
3530 cycles (condition 4)
4332 cycles
2155 cycles (condition 3)
3125 cycles
3122 cycles (condition 4)
4256 cycles
2004 cycles (condition 3)
639 cycles (condition 1)
3198 cycles
3694 cycles (condition 4)
4089 cycles
2037 cycles (condition 3)
639 cycles (condition 1)
410 cycles (condition 1)
3110 cycles
3271 cycles (condition 4)
3903 cycles
1891 cycles (condition 3)
468 cycles (condition 1)
337 cycles (condition 1)
371 cycles (condition 1)
2970 cycles
3459 cycles (condition 4)
3867 cycles
1860 cycles (condition 3)
419 cycles (condition 1)
350 cycles (condition 1)
423 cycles (condition 1)
407 cycles (condition 1)
3040 cycles
3289 cycles (condition 4)
3864 cycles
2037 cycles (condition 3)
389 cycles (condition 1)
404 cycles (condition 1)
435 cycles (condition 1)
371 cycles (condition 1)
398 cycles (condition 1)
```

マッチングにかかるCPUサイクル及びメモリ使用量に関して。

まずCPUサイクルですが、上の出力のようになりました。
若い番号の条件を根拠にREJECTEDとなった回の呼び出しほど消費サイクル数が小さくなっています。
これは条件の判定を順に行なっていくためです。
また、初回のマッチングの実行は他の10倍ほどのサイクル数を消費しています。
これは命令等に関するキャッシュがまだ効いていないことが原因だと考えられます。

メモリ使用量に関してですが、個別の関数ごとあるいは個別の呼び出しごとのそれに関する計測は難しかったため、おおまかに述べます。
ある実行において、valgrind/massifを用いて計測したところ、以下のような結果を得ました。
数百バイトほどのスタックのみを消費していると読むことができます。
今回使用したパケットの大きさが、 2 + 20 + 20 + (20程度) であることからも、この程度のみであるのは自然です。
ヒープの消費がありませんが、これは今回実装したマッチング関数中では std::string を新しく確保することはないためです。

```
  n       time(ms)         total(B)   useful-heap(B) extra-heap(B)    stacks(B)
--------------------------------------------------------------------------------
 46          1,455           77,344           76,842            54          448  (マッチング関数呼び出し直前)
 53          5,541           77,688           76,842            54          792  (マッチング関数中のある箇所)
```


## 選択問題.8

以下のダンプはあるプログラムのobjdumpの結果である。このプログラムが行っていることを調べ、その結果を記述してください。完全には分からなくても構いませんので、理解できたところまでの情報や調査の過程で使ったツール、感じたこと等について記述してください。

```
$ objdump -d challenge00
challenge00:     ファイル形式 elf64-x86-64

セクション .text の逆アセンブル:

0000000000400080 <.text>:
 400080:    68 19 01 40 00           pushq  $0x400119
 400085:    6a 01                    pushq  $0x1
 400087:    68 06 01 40 00           pushq  $0x400106
 40008c:    68 19 01 40 00           pushq  $0x400119
 400091:    68 29 01 40 00           pushq  $0x400129
 400096:    6a 3c                    pushq  $0x3c
 400098:    68 02 01 40 00           pushq  $0x400102
 40009d:    68 10 01 40 00           pushq  $0x400110
 4000a2:    48 b8 36 15 1b 25 67     movabs $0x63391a67251b1536,%rax
 4000a9:    1a 39 63 
 4000ac:    50                       push   %rax
 4000ad:    68 02 01 40 00           pushq  $0x400102
 4000b2:    6a 00                    pushq  $0x0
 4000b4:    68 06 01 40 00           pushq  $0x400106
 4000b9:    68 14 01 40 00           pushq  $0x400114
 4000be:    68 0c 01 40 00           pushq  $0x40010c
 4000c3:    68 02 01 40 00           pushq  $0x400102
 4000c8:    68 26 01 40 00           pushq  $0x400126
 4000cd:    68 14 01 40 00           pushq  $0x400114
 4000d2:    6a 07                    pushq  $0x7
 4000d4:    68 0a 01 40 00           pushq  $0x40010a
 4000d9:    6a e0                    pushq  $0xffffffffffffffe0
 4000db:    68 08 01 40 00           pushq  $0x400108
 4000e0:    68 19 01 40 00           pushq  $0x400119
 4000e5:    6a 08                    pushq  $0x8
 4000e7:    68 04 01 40 00           pushq  $0x400104
 4000ec:    6a 00                    pushq  $0x0
 4000ee:    68 1c 01 40 00           pushq  $0x40011c
 4000f3:    6a 00                    pushq  $0x0
 4000f5:    68 06 01 40 00           pushq  $0x400106
 4000fa:    6a 00                    pushq  $0x0
 4000fc:    68 02 01 40 00           pushq  $0x400102
 400101:    c3                       retq   
 400102:    58                       pop    %rax
 400103:    c3                       retq   
 400104:    5a                       pop    %rdx
 400105:    c3                       retq   
 400106:    5f                       pop    %rdi
 400107:    c3                       retq   
 400108:    5d                       pop    %rbp
 400109:    c3                       retq   
 40010a:    59                       pop    %rcx
 40010b:    c3                       retq   
 40010c:    48 01 ec                 add    %rbp,%rsp
 40010f:    c3                       retq   
 400110:    48 39 06                 cmp    %rax,(%rsi)
 400113:    c3                       retq   
 400114:    80 34 0e 55              xorb   $0x55,(%rsi,%rcx,1)
 400118:    c3                       retq   
 400119:    0f 05                    syscall 
 40011b:    c3                       retq   
 40011c:    48 89 e6                 mov    %rsp,%rsi
 40011f:    41 5a                    pop    %r10
 400121:    c3                       retq   
 400122:    48 89 f1                 mov    %rsi,%rcx
 400125:    c3                       retq   
 400126:    48 ff c9                 dec    %rcx
 400129:    75 01                    jne    0x40012c
 40012b:    c3                       retq   
 40012c:    41 5a                    pop    %r10
 40012e:    c3                       retq   
```

### 解答

このプログラムは、ROP (return oriented programming)を用いて動作し、入力が`c@Np2Ol6`という文字列であるかを判定するプログラムです。

詳細な挙動に関して。
read システムコールにより8byteの文字列を読み込み、その各バイトの0x55との排他的論理和をとり、結果のバイト列を特定のバイト列とcmp命令を用いて比較します。このとき、元々の入力文字列が`c@Np2Ol6`であったならば、その比較対象と一致します。その後、exit システムコールにより停止します。この際リターンコードが、文字列が一致していれば0になり、そうでなければ1になります。

上記の動作の実現には、ROPが応用されています。
特にこの場合、ある種の継続渡しによるプログラミングとして説明できます。
次に実行するべき処理を表すアドレスを追加で引数のようにして取り、目的の処理を実行した後引数で渡された続きの処理へ実行を移す、そのような処理の断片を積み上げることによりプログラムを構成しています。
また、ROPのための継続が積まれたスタック上でのループの実現のために、rsp の値をいくらか減らすことでスタックを巻き戻しています。rspより低位の領域上の値は今回は変化しないので、それをそのまま再利用しています。そのような場所の値も、何もしなければそのまま変化しませんが、通常の関数を呼び出す等するとその関数に破壊されてしまうことがあるので一般には注意が必要です。

調査の仮定で使ったツールは、nasm <http://www.nasm.us/>とqira <http://qira.me/>です。
テキスト領域の中身は全て与えられているため、それを元にnasmを使い実行可能なバイナリを復元し、qiraを用いて動作を確認しました。


## 選択問題.10

まずは以下のプログラムを物理PCと複数の仮想化ソフトウェア（qemu、 VMware、 Virtual PCなど）を使って実行し、それぞれの結果の違いを確認してください。そして、なぜそうした結果が得られたのか、物理PCと同じ振る舞いを実現するには仮想化ソフトウェアをどのように改造すればよいかを考察し、その内容を記述してください。
 
``` c
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
 
void sighandler()
{
   printf("OK\n");
   exit(0);
}
 
__asm__("check00:\n\
   mov $0x564D5868, %eax\n\
   mov $0xa, %cx\n\
   mov $0x5658, %dx\n\
   in %dx, %eax\n\
   ret\n\
");
void check00();
 
__asm__("check01:\n\
   .byte 0xf3,0xf3,0xf3,0xf3,0xf3\n\
   .byte 0xf3,0xf3,0xf3,0xf3,0xf3\n\
   .byte 0xf3,0xf3,0xf3,0xf3,0xf3\n\
   ret\n\
");
int check01();
 
__asm__("check02:\n\
   .byte 0x0f,0x3f,0x07,0x0b\n\
   ret\n\
");
int check02();
 
int main(int argc, char **argv)
{
   int cmd;
   if(argc == 2){
       cmd = atoi(argv[1]);
   }else{
       printf("USAGE: %s <command>\n", argv[0]);
       exit(1);
   }
   signal(SIGSEGV, sighandler);
   signal(SIGILL, sighandler);
   switch(cmd){
   case 0: check00(); break;
   case 1: check01(); break;
   case 2: check02(); break;
   default: exit(1);
   }
   printf("NG\n");
   return 1;
}
```

### 解答

実機 (Ubuntu 16.04 LTS 64-bit)、VMware (VMware Workstation 12 Player + Ubuntu 16.04 LTS 64-bit)、QEMU (qemu-x86_64 version 2.5.0)、VirtualBox (Version 5.0.18_Ubuntu) でそれぞれ実行しました。

実機では全てOKが出力されました。特に、シグナルハンドラを設定しなかった場合の出力はそれぞれ以下のようになりました。

```
segmentation fault (core dumped)
segmentation fault (core dumped)
illegal hardware instruction (core dumped)
```

VMwareでの実行は、check00がNGでした。
QEMUでの実行は、check01がNGでした。
VirtualBoxでの実行は、全てOKでした。


VMwareでcheck00がNGであった理由に関して。
check00はVMwareのbackdoor I/O portを叩いています。
backdoor I/O portとは、ホスト側であるVMwareが、ゲスト側のOSと通信するために使われるI/O portで、これはユーザアプリケーションからも利用することができます。
一般の環境ではI/O portのユーザアプリケーションからの利用はsegmentation faultとなります。
ゲスト側で、eaxにマジックナンバー"VMXh"を入れecxにコマンド番号を入れて0x5658番ポートにin命令でアクセスすることで、ホスト側の機能を呼び出します。
特に今回のそれはecx = 0xaであるのでVMwareのversion情報を取得しています。
これはeax, ecxに結果の値を代入するもので、実際にgdbで確認すると、eax, ecxにそれぞれ6, 4が代入されていました。
これらのコマンドに関する非公式なドキュメントとしては、 <https://sites.google.com/site/chitchatvmback/backdoor#cmd0ah> があります。


QEMUでcheck01がNGであった理由に関して。
これは、実際のCPUにおけるx86の命令長の制限が15byteであるが、QEMUはソフトウェアによるエミュレーションであるためそのような制限を持たない、という差によるものです。
0xf3はx86/x64ではrepz prefixであり、15個のrepzと1個のrepによる16byteの命令はこの制限による挙動の差を生み出します。
よってこの命令はQEMUでのみ実行されることとなります。
Artem Dinaburgらによる、Ether: Malware Analysis via Hardware Virtualization Extensions <https://www.damballa.com/downloads/a_pubs/CCS08.pdf> に記載されています。


check02がNGになるような環境についてですが、これはVirtual PCが該当するようです。
0x0F 0x3F 0x07 0x0B という通常は不正な命令を、ホスト側OSとの通信用に用いており、OKとはならないようです。
検索すると、 <http://ku.ido.nu/post/90224067584/can-detect-we-are-in-virtual-machine> のような記事が発見できます。

---

-   Thu Jun 16 15:50:40 JST 2016
    -   他人の応募用紙を見つけたので追加
