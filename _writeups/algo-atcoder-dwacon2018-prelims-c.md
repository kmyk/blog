---
layout: post
redirect_from:
  - /writeup/algo/atcoder/dwacon2018-prelims-c/
  - /blog/2018/01/14/dwacon2018-prelims-c/
date: "2018-01-14T03:41:55+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2018-prelims/tasks/dwacon2018_prelims_c" ]
---

# 第4回 ドワンゴからの挑戦状 予選: C - Kill/Death

C以降では最も難しいと思います。

写像12相という言葉は知らなかったので勉強になった。

-   [写像の個数（写像12相） \| 高校数学の美しい物語](https://mathtrain.jp/twelveway)
-   [n個のボールをm個の箱に入れよう - kuno4n&#39;s blog](http://kuno4n.hateblo.jp/entry/2013/12/14/140104#count8)

## solution

DP。$i$番目のプレイヤーまでdeath数を決定しそれまでの総和が$j$であるときの場合の数を$\mathrm{dp}(i, j)$と置く。$O(n \sum\_j \mathrm{killB}\_j + m \sum\_i \mathrm{killA}\_i)$。

難しいのはkill数が同じプレイヤーが複数いたとき。
それらの中ではdeath数が昇順にならなければならない。
これはdeath数をそれらプレイヤーにまとめて配ることで解決できる。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">Cむずかった　自分のうしろに自分と同じkill数の人たちがいる場合は自分に1配る=後ろの人にも1配るということに気をつけるとdp(i, 残り何個配れる) で前の人からdeath数を決定できる</p>&mdash; アルハンブラ宮殿のゆるキャラ (@nebukuro09) <a href="https://twitter.com/nebukuro09/status/952164252315299840?ref_src=twsrc%5Etfw">2018年1月13日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

constexpr int mod = 1e9 + 7;

int func(vector<int> const & kill, int sum_death) {
    int n = kill.size();
    vector<int> cur(sum_death + 1);  // main DP
    vector<int> prv(sum_death + 1);
    cur[0] = 1;
    REP (l, n) {
        int r = l + 1;
        while (r < n and kill[l] == kill[r]) ++ r;
        cur.swap(prv);
        REP (j, min(r - l, sum_death + 1)) {
            cur[j] = prv[j];
        }
        REP3 (j, r - l, sum_death + 1) {
            cur[j] = cur[j - (r - l)] + prv[j];
            if (cur[j] >= mod) cur[j] -= mod;
        }
    }
    return cur[sum_death];
}

int main() {
    // input
    int n, m; cin >> n >> m;
    vector<int> kill_a(n); REP (i, n) cin >> kill_a[i];
    vector<int> kill_b(m); REP (i, m) cin >> kill_b[i];
    // solve
    int sum_kill_a = accumulate(ALL(kill_a), 0);
    int sum_kill_b = accumulate(ALL(kill_b), 0);
    int x = func(kill_a, sum_kill_b);
    int y = func(kill_b, sum_kill_a);
    int result = x *(long long) y % mod;
    // output
    cout << result << endl;
    return 0;
}
```
