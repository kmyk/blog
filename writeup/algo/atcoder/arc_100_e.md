---
layout: post
date: 2018-07-01T23:13+09:00
tags: [ "atcoder", "arc", "competitive", "writeup", "fast-zeta-transformation" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc100/tasks/arc100_c" ]
redirect_from:
  - /writeup/algo/atcoder/arc-100-e/
---

# AtCoder Regular Contest 100: E - Or Plus Max

## solution

$i$の選択が$j$の選択に影響を与える桁DPみたいな雰囲気が難しさ。
そこで制約を$\le K$から$= K$にする(典型 1)が思い付く。
これはbit DPでできる。
<span>$A_i + A_j$</span>を持つと不足なので$(i, j)$を持つ(典型 2)。
$O(N 2^N)$。

よく見ると高速$\zeta$変換の形だが、和の演算に冪等性があるので実装は雑にbit DPできる。
sortを雑にやると$O(N 2^N \log N)$だが誤差なのでよい。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int n; cin >> n;
    vector<int> a(1 << n);
    REP (i, 1 << n) cin >> a[i];

    // solve
    vector<pair<int, int> > choice(1 << n, make_pair(-1, -1));
    REP3 (k, 1, 1 << n) {
        vector<int> cands;
        cands.push_back(0);
        cands.push_back(k);
        REP (i, n) if (k & (1 << i)) {
            int l = k ^ (1 << i);
            if (l == 0) continue;
            cands.push_back(choice[l].first);
            cands.push_back(choice[l].second);
        }
        sort(ALL(cands), [&](int i, int j) { return a[i] > a[j]; });
        unique(ALL(cands));
        choice[k] = make_pair(cands[0], cands[1]);
    }
    vector<int> ans(1 << n);
    REP3 (k, 1, 1 << n) {
        int i, j; tie(i, j) = choice[k];
        ans[k] = a[i] + a[j];
        chmax(ans[k], ans[k - 1]);
    }

    // output
    REP3 (k, 1, 1 << n) {
        cout << ans[k] << endl;
    }
    return 0;
}
```
