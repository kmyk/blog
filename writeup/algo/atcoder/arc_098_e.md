---
layout: post
date: 2018-10-12T00:37:46+09:00
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc098/tasks/arc098_c" ]
redirect_from:
  - /writeup/algo/atcoder/arc_098_e/
  - /writeup/algo/atcoder/arc-098-e/
---

# AtCoder Regular Contest 098: E - Range Minimum Queries

## 解法

### 概要

最小値$Y$を固定し、それぞれについて$X$を最小化。
$O(N^2 \log N)$。

## メモ

-   editorialの

    >   余談ですが、実はこの問題は $N \le 10^5$ で解くことが出来ます。

    はおそらく$O(N \log N)$。
    最小値$Y$を大きい側から順番に試していくことで、ひとつ前の$Y$からいくつか使えるものが増えるのでこれを差分更新していけばよいだろう。

-   「$X - Y$ を最大化」と誤読するとWavelet Matrixチャンスになる。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T, class U> inline void chmin(T & a, U const & b) { a = min<T>(a, b); }

constexpr int BITS = 30;
int solve(int n, int k, int q, vector<int> const & a) {
    int answer = INT_MAX;
    set<int> ys(ALL(a));
    for (int y : ys) {
        vector<int> c;
        for (int l = 0; l < n; ) {
            int r = l;
            while (r < n and a[r] >= y) ++ r;
            if (r - l >= k) {
                vector<int> b(a.begin() + l, a.begin() + r);
                sort(ALL(b));
                c.insert(c.end(), b.begin(), b.begin() + (r - l - k + 1));
            }
            l = r + 1;
        }
        sort(ALL(c));
        if (q - 1 < c.size()) {
            int x = c[q - 1];
            chmin(answer, x - y);
        }
    }
    return answer;
}

int main() {
    int n, k, q; cin >> n >> k >> q;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    cout << solve(n, k, q, a) << endl;
    return 0;
}
```
