---
layout: post
alias: "/blog/2016/01/20/srm-679-hard/"
date: 2016-01-20T23:42:15+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "convolution" ]
---

# TopCoder SRM 679 div1 Hard: BagAndCards

問題文は明らかに*HARD*だったけど、問題は難しめのeasyぐらいだったように思える。
本番では問題の理解でかなりの時間を消費し、時間がない中fftだと踏んで実装しようとしていた。後から落ち着いて考えたらもっと簡単だった。
また、使っているpluginのgreedが自動生成したサンプルが壊れていて、これに気付くのにも時間がかかった。

## [BagAndCards]()

### 問題

鞄が$n$個ある。それぞれの鞄$i$には数$j$が書かれたカードが${\rm count}\_{i,j}$個入っている。カードは同じ数が書かれていてもそれぞれ区別する。
鞄$i$と鞄$j$からカードをそれぞれ$1$枚ずつ、ただしカードに書かれた数の和が$k$になるように取り出す方法の数を$w\_{i,j,k}$とする。
数の集合$G \subset { 0 \dots 2m-2 }$が与えられる。
和が$G$に含まれるような取り出し方${\rm ans}\_{i,j} = \Sigma\_{k \in G} w\_{i,j,k}$を求め、その排他的論理和に関する総和$\Sigma\_{i,j}^\oplus {\rm ans}\_{i,j}$を答えよ。

### 解法

convolutionであるがその後その総和を取るため、これを利用して簡単に計算することができる。$O(n^2m)$。

$a_k = {\rm count}\_{i,k}$, $b_k = {\rm count}\_{j,k}$として$w\_{i,j,k} = \Sigma_h a_h b\_{k-h}$である。
この重み付き総和は$\Sigma\_{k \in G} w\_{i,j,k} = \Sigma\_{k \in G} \Sigma_h a_h b\_{k-h} = \Sigma_h \Sigma\_{k \in G} a_h b\_{k-h} = \Sigma_h ( a_h \Sigma\_{k \in G} b\_{k-h} )$と変換できて、$c_h = \Sigma\_{k \in G} b\_{k-h}$と事前に計算しておけば、$\Sigma_h a_h c_h$として計算できる。

"target_url": [ "small" ]
---

# TopCoder SRM 679 div1 Hard: BagAndCards
正答者の解答を眺めた限り、fftだとtleするようだ。
そもそも、私の持っていたfft(fast fourier transformation)のlibraryを貼ったところ、おそらく誤差のためにサンプルが合わなかった。誤差に関してはntt(number-theoritical transformation)というのを使えばよいのだろうか。
</small>

### 実装

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class BagAndCards { public: int getHash(int n, int m, int x, int a, int b, int c, string isGood); };

const int mod = 1e9+7;
int BagAndCards::getHash(int n, int m, int x, int a, int b, int c, string isGood) {
    vector<vector<int> > cnt(n, vector<int>(m));
    repeat (i,n) {
        repeat (j,m) {
            cnt[i][j] = x;
            x = ((ll(x) * a + b) ^ c) % mod;
        }
    }
    int ans = 0;
    repeat (j,n) {
        vector<int> sum(m);
        repeat (i,m) repeat (k,m) if (isGood[i+k] == 'Y') {
            sum[i] = (sum[i] + cnt[j][k]) % mod;
        }
        repeat (i,j) {
            int ans_i_j = 0;
            repeat (k,m) ans_i_j = (ans_i_j + ll(cnt[i][k]) * sum[k] % mod) % mod;
            ans ^= ans_i_j;
        }
    }
    return ans;
}
```
