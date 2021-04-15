---
layout: post
redirect_from:
  - /writeup/algo/atcoder/abc_089_d/
  - /writeup/algo/atcoder/abc-089-d/
  - /blog/2018/03/06/abc-089-d/
date: "2018-03-06T23:37:08+09:00"
tags: [ "competitive", "writeup", "atcoder", "abc", "cumulative-sum" ]
"target_url": [ "https://beta.atcoder.jp/contests/abc089/tasks/abc089_d" ]
---

# AtCoder Beginner Contest 089: D - Practical Skill Test

ちょくだいさんが以下のようなことを言っていたので解いた。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">ABCのD問題、「これ400はオーバーキルでしょー」って終わった後見て思ってたんだけど、Dがクエリで与えられるわけじゃなくて、固定で最初に与えられるのね。それならオーバーキルではない。（クエリに与えられても解けるよ）<a href="https://t.co/j1LWpuzk6n">https://t.co/j1LWpuzk6n</a></p>&mdash; chokudai(高橋 直大) (@chokudai) <a href="https://twitter.com/chokudai/status/970932654794203137?ref_src=twsrc%5Etfw">2018年3月6日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## solution

累積和。$O(HW + Q)$。

以下のdisjoint制約が強い。$A\_{i, j} \bmod D$で分類してそれぞれで累積和を取る感じでやる。

>   $1$から$H \times W$までの整数が重複なく書かれており、

$D$がクエリとして与えられた場合は <del>$O(HW (\log HW)^2)$でEratosthenesの篩っぽくやればよいはず</del>
整数$K = f(HW, Q)$を固定して$D \le K$で分岐。$D \le K$なら累積和で$O(HWK + Q)$、$D \ge K$なら愚直に$O(Q \cdot HW/K)$。
$Kの選択は$\sqrt{Q}$として全体で$O(HW\sqrt{Q} + Q)$が最適のはず。

一方でdisjoint制約がなかった場合はかなり難しくなるはず。すこし考えた限りでは分からなかった。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int h, w, d; scanf("%d%d%d", &h, &w, &d);
    vector<int> y(h * w);
    vector<int> x(h * w);
    REP (j, h) REP (i, w) {
        int a; scanf("%d", &a);
        -- a;
        y[a] = j;
        x[a] = i;
    }

    // solve
    vector<vector<int> > acc = vectors(d, h * w / d + 1, int());
    REP (i, h * w - d) {
        acc[(i + d) % d][(i + d) / d] = acc[i % d][i / d]
            + abs(y[i + d] - y[i])
            + abs(x[i + d] - x[i]);
    }
    auto solve = [&](int l, int r) {
        return acc[r % d][r / d] - acc[l % d][l / d];
    };

    // output
    int q; scanf("%d", &q);
    while (q --) {
        int l, r; scanf("%d%d", &l, &r);
        -- l;
        -- r;
        printf("%d\n", solve(l, r));
    }
    return 0;
}
```

<hr>

-   2018年  3月  8日 木曜日 13:15:45 JST
    -   入力を緩めた場合の解法を修正
    -   実装してない解法について言及するのはだめですね。方向としては合ってたし本番書かされてたら気付いてたとは思うのですが。
