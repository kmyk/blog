---
layout: post
alias: "/blog/2018/01/14/dwacon2018-prelims-d/"
title: "第4回 ドワンゴからの挑戦状 予選: D - ディスクの節約"
date: "2018-01-14T03:41:57+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "dp", "tree", "bit-dp", "dijkstra" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2018-prelims/tasks/dwacon2018_prelims_d" ]
---

木DPして死。$1$WAだけなのいやらしい。

## solution

木DPは嘘。まとめてbit DPする。
実行結果がディスク上に書き込まれているデータの集合を$s$とし、そのような状況を作る過程における最大のディスク使用量を$\mathrm{dp}(s)$とする。
更新はDijkstraっぽくやるとよい。
$O(N2^N)$。

木DPの反例は `02_tayama_killer00` としてシステムテスト中に(ひとつだけ)存在する。小さな例だと次のようなもの。

```
8
7 9 3 4 7 9 4 9
1 1 3 2 4 5 5
```

逆からやれば単にDFSみたいな話を聞いたが聞いただけ。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;

int main() {
    // input
    int n; cin >> n;
    vector<int> x(n);
    REP (i, n) cin >> x[i];
    vector<vector<int> > children(n);
    REP (i, n - 1) {
        int a; cin >> a; -- a;
        children[a].push_back(i + 1);
    }
    // solve
    vector<int> dependency(n);
    REP (i, n) {
        for (int j : children[i]) {
            dependency[i] |= 1 << j;
        }
    }
    vector<int> sum_x(1 << n); {
        sum_x[0] = 0;
        REP3 (s, 1, 1 << n) {
            int k = __builtin_ctz(s);
            int t = s ^ (1 << k);
            sum_x[s] = sum_x[t] + x[k];
        }
    }
    vector<int> dp(1 << n, INT_MAX); {
        reversed_priority_queue<pair<int, int> > que;  // dijkstra
        dp[0] = 0;
        que.emplace(dp[0], 0);
        while (not que.empty()) {
            int dp_s, s; tie(dp_s, s) = que.top(); que.pop();
            if (dp[s] < dp_s) continue;
            REP (k, n) if (not (s & (1 << k)) and (s == (s | dependency[k]))) {
                int t = (s | (1 << k)) & (~ dependency[k]);
                int dp_t = max(dp[s], sum_x[s | (1 << k)]);
                if (dp_t < dp[t]) {
                    dp[t] = dp_t;
                    que.emplace(dp[t], t);
                }
            }
        }
    }
    // output
    cout << dp[1] << endl;
    return 0;
}
```
