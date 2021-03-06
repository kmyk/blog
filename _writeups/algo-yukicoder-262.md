---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/262/
  - /blog/2016/02/27/yuki-262/
date: 2016-02-27T04:00:30+09:00
tags: [ "competitive", "writeup", "yukicoder", "bit", "dp" ]
---

# Yukicoder No.262 面白くないビットすごろく

練習会で。
後輩が全部考察した。ビット演算は触ったことがないとかなんとか言いながら解法を叩き出してた。
私は分からなかったので彼の考察に従ってそのまま書きました。

$1$ステップで高々$40$程度しか増加しないので、頻繁に変化するのは下位ビットだけ、という点から進めばよかったのだろうか。
あるいはもっと一般的に、頻繁に変化する部分とそうでない部分に分ける、だろうか。
ともあれ上位ビットと下位ビットに分ける発想はその内また出てくるだろうので覚えておきたい。

## [No.262 面白くないビットすごろく](http://yukicoder.me/problems/402)

### 解法

上位ビットと下位ビットに分けて上手にやる。だいたい$O(\sqrt{N} \log{N})$ぐらいだろう。
[editorial](http://yukicoder.me/problems/402/editorial)曰く埋め込みでもよいっぽい。

頻繁に変化するのは下位ビットだけであるので、上位ビットと下位ビットに分ける。
上位ビットはときおりincrementされるだけであるので、上位ビットのpopcountが$h$で下位ビットが$l$であるとき、上位ビットが増えるまでのステップ数$S\_{h,l}$と、増えた直後の下位ビットの状態$L\_{h,l}$を事前に計算する。これに基づき$1$マス目から$N$マス目に向けて進んでいけばよい。

$N \le 10^{12}$であるが、$\log{10^{12}} \approx 39.863$なので、上位$20$ビットと下位$20$ビット。
$0 \le h \lt 20$で$0 \le l \le 2^{20} \approx 10^6$なので、前処理は$hl$個のテーブルであるので間に合う。
テーブルに従う大ステップ$1$回で上位ビットが$1$増加、つまりマス目が$2^{20}$進むので、本計算は$2^{20}$回程度で抑えられる。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
int main() {
    // input
    ll n; cin >> n;
    assert (n <= 1e12);
    const int l = 20; // log 10^12 < 40
    const int mask = (1<<l) - 1;
    // make table
    vector<vector<int> > cnt(l, vector<int>(1<<l));
    vector<vector<int> > bit(l, vector<int>(1<<l));
    repeat (i,l) {
        repeat_reverse (j,1<<l) {
            int k = j + __builtin_popcount(j) + i;
            if (mask < k) {
                cnt[i][j] = 1;
                bit[i][j] = k & mask;
            } else {
                cnt[i][j] = 1 + cnt[i][k];
                bit[i][j] = bit[i][k];
            }
        }
    }
    // simulate
    ll ans = 1;
    ll ah = 0, al = 1;
    while (true) {
        int popcount_ah = __builtin_popcount(ah);
        ll bh = ah + 1;
        ll bl = bit[popcount_ah][al];
        ll b = (bh << l) + bl;
        if (n < b) break;
        ans += cnt[popcount_ah][al];
        ah = bh;
        al = bl;
    }
    int popcount_ah = __builtin_popcount(ah);
    ll nl = n & mask;
    while (al < nl) {
        ans += 1;
        al += popcount_ah + __builtin_popcount(al);
    }
    ll a = (ah << l) + al;
    if (a != n) ans = -1;
    // output
    cout << ans << endl;
    return 0;
}
```
