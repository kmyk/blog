---
redirect_from:
  - /writeup/algo/yukicoder/710/
layout: post
date: 2018-06-30T02:13+09:00
tags: [ "competitive", "writeup", "yukicoder", "dp" ]
"target-url": [ "https://yukicoder.me/problems/no/710" ]
---

# Yukicoder No.710 チーム戦

## 解法

$i$番目まで見てAさんが$a$秒使ったときのBさんの使う時間の最小値を<span>$b = \mathrm{dp}_i(a)$</span>とするDP。
<span>$O(n\sum A_i)$</span>。

述語$\mathrm{dp} : H \times W \to 2$を関数<span>$\mathrm{dp} : H \to W \cup \\{ \star \\}$</span>の形にして加速するのは典型テク。
蟻本。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

int main() {
    // input
    int n; cin >> n;
    vector<int> a(n), b(n);
    REP (i, n) cin >> a[i] >> b[i];

    // solve
    int sum_a = accumulate(ALL(a), 0);
    vector<int> cur(sum_a + 1, INT_MAX);
    cur[0] = 0;
    REP (i, n) {
        vector<int> nxt(sum_a + 1, INT_MAX);
        REP (x, sum_a + 1) if (cur[x] != INT_MAX) {
            if (x + a[i] <= sum_a) {
                chmin(nxt[x + a[i]], cur[x]);
            }
            chmin(nxt[x], cur[x] + b[i]);
        }
        cur.swap(nxt);
    }
    int answer = INT_MAX;
    REP (x, sum_a + 1) if (cur[x] != INT_MAX) {
        chmin(answer, max(x, cur[x]));
    }

    // output
    cout << answer << endl;
    return 0;
}
```
