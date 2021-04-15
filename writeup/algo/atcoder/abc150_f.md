---
redirect_from:
layout: post
date: 2020-01-11T23:59:59+09:00
tags: ["competitive", "writeup"]
---

# AtCoder Beginner Contest 150: F - Xor Shift

## 解法

別解たくさんだったので。私は乱択派

### 想定解: 階差

$a _ {k + i} \oplus x = b _ i$ かつ $a _ {k + i + 1} \oplus x = b _ {i + 1}$ なので $a _ {k + i} \oplus a _ {k + i + 1} = b _ i \oplus b _ {i + 1}$ である。$a$ の階差と $b$ の階差をそれぞれ取って一致するように回転させればその回転量が所望の $k$ である。$O(N)$。それはそうだけど天才か？

### 非想定: 乱択

$k$ を固定すると (その時点で) 唯一の候補である $x = a _ {k + i} \oplus b _ i$ がひとつ得られる。
すべての $j$ について $x = a _ {k + j} \oplus b _ j$ であるか判定すればよい。
これをすべての $j$ についてでなく適当な $K = 100$ 個ぐらいとやれば間に合いがち。$O(NK)$。

ただし、とりあえず思い付く乱択対策が $a = (0, 0, 0, \dots, 0)$ で $b = (0, 0, 0, \dots, 0, 1, 0, 0, 0, \dots, 0)$ みたいなやつで、この乱択対策の対策ぐらいはしておく必要がありそう。

### 非想定: rolling hash

bit ごとに独立に rolling hash (あるいは KMP 法でもよい) をしてその $k$ の共通部分を取る。bit 数 $B = 30$ が乗って $O(NB)$。

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">F、bit 毎に分けて毎回ロリハした<br>クソ雑実装で 1000ms、安い</p>&mdash; 熨斗袋 (@noshi91) <a href="https://twitter.com/noshi91/status/1215631546016645121?ref_src=twsrc%5Etfw">January 10, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-conversation="none"><p lang="ja" dir="ltr">あと bit ごとに見て flip する O(bN) みたいのも微妙な気持ちになったし、N&lt;=10^6、a_i,b_i &lt; 2^60 みたいな過激派になった方がよかったかもしれない</p>&mdash; 紙ぺーぱー (@camypaper) <a href="https://twitter.com/camypaper/status/1215663650167390208?ref_src=twsrc%5Etfw">January 10, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

### 非想定: 枝刈り

<blockquote class="twitter-tweet"><p lang="ja" dir="ltr">Fテスターでしたが、微妙に枝刈り通されててすみません〜と言っています</p>&mdash; ctrl+W (@latte0119_) <a href="https://twitter.com/latte0119_/status/1215660356611133441?ref_src=twsrc%5Etfw">January 10, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-conversation="none"><p lang="ja" dir="ltr">こういうのは枝刈り落とし切るのは無理…(N を大きくして提案しておけばよかったですね、すいません…)</p>&mdash; 紙ぺーぱー (@camypaper) <a href="https://twitter.com/camypaper/status/1215661182238916610?ref_src=twsrc%5Etfw">January 10, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## メモ

-   <https://atcoder.jp/contests/abc150/tasks/abc150_f>
