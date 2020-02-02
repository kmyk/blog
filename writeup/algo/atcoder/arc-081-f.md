---
layout: post
alias: "/blog/2017/08/21/arc-081-f/"
date: "2017-08-21T00:12:19+09:00"
title: "AtCoder Regular Contest 081: F - Flip and Rectangles"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc081/tasks/arc081_d" ]
---

解けず。

意識するようにしたい: <blockquote class="twitter-tweet" data-lang="en"><p lang="ja" dir="ltr">なんか詰まった時にとりあえず試すといいやつがあって、<br>・累積和をとる<br>・階差をとる<br>・階差xor(?)(隣り合う項のxor)をとる<br>あたりは結構重要だなあとなる(例えば区間に一様に加算するときは累積和をとると変更箇所が2箇所になって扱いやすいし、今回のFも階差xorで解ける)</p>&mdash; らて (@LatteMalta) <a href="https://twitter.com/LatteMalta/status/899274453976088576">August 20, 2017</a></blockquote>
<script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

## solution

$O(HW)$。

長方形の左上$(l\_x, l\_y)$と左下$(l\_x, r\_y)$を固定してできるだけ右に伸ばすことを考える。
好きな行のマスの反転ができるので、各行$y$で点$(l\_x, l\_y)$の色を左上に揃えるように反転させる。
各列の各点でそれより右で最初に色の切り替わる点を求めておいて区間minクエリで求まる。
ただしその区間$[l\_y, r\_y]$でのminが全て一致していた場合は、その次の列を反転させることで長方形を伸ばせてしまう。

ここまでだと$O(H^2W)$だが、次の$2$点を使えば$O(HW)$。

-   長方形をこれ以上伸ばせない点を一発で得るには、各行の色の変化でなくて、隣接する行ごとの不一致に注目する
-   区間minクエリを$O(H^2)$回発行するのでなくて、ヒストグラム中の面積を求めるようなstackを使ったテクで$O(H)$

## implementation

``` c++
#include <iostream>
#include <stack>
#include <tuple>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    // input
    int h, w; cin >> h >> w;
    vector<string> s(h);
    repeat (y, h) cin >> s[y];
    // solve
    auto hist = vectors(h - 1, w, int());
    repeat (y, h - 1) {
        hist[y][w - 1] = 1;
        repeat_reverse (x, w - 1) {
            bool p = ((s[y][x] == s[y + 1][x]) == (s[y][x + 1] == s[y + 1][x + 1]));
            hist[y][x] = (p ? hist[y][x + 1] + 1 : 1);
        }
    }
    int result = w;
    repeat (x, w - 1) {
        stack<pair<int, int> > stk;
        repeat (i, (h - 1) + 1) {
            int h_i = (i < h - 1 ? hist[i][x] : 0);
            int j = i;
            while (not stk.empty() and stk.top().second > h_i) {
                int h_j; tie(j, h_j) = stk.top();
                stk.pop();
                setmax(result, h_j * (i - j + 1));
            }
            if (stk.empty() or stk.top().second < h_i) {
                stk.emplace(j, h_i);
            }
        }
    }
    // output
    printf("%d\n", result);
    return 0;
}
```
