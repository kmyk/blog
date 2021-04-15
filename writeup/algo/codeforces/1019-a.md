---
redirect_from:
  - /writeup/algo/codeforces/1019-a/
layout: post
date: 2018-08-12T03:48:17+09:00
tags: [ "competitive", "writeup", "codeforces", "greedy" ]
"target_url": [ "https://codeforces.com/contest/1019/problem/A" ]
---

# Codeforces Round #503 (by SIS, Div. 1): A. Elections

## solution

党$1$以外の党の標数の最大値を総当たり。
貪欲。
決め打ちした最大値より多い部分は固定で買収し、それ以下の部分は必要に応じて全体の中で安い順に買収。
$O(n m \log m)$。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }

int main() {
    // input
    int n, m; cin >> n >> m;
    vector<int> p(n);
    vector<ll> c(n);
    vector<vector<ll> > g(m);
    REP (i, n) {
        cin >> p[i] >> c[i];
        -- p[i];
        g[p[i]].push_back(c[i]);
    }

    // solve
    REP (j, m) {
        sort(g[j].rbegin(), g[j].rend());
    }
    ll ans = LLONG_MAX;
    REP (cnt1, n) {
        int cnt0 = g[0].size();
        ll cost = 0;
        reversed_priority_queue<ll> que;
        REP3 (j, 1, m) {
            REP (k, g[j].size()) {
                if (k < cnt1) {
                    que.push(g[j][k]);
                } else {
                    ++ cnt0;
                    cost += g[j][k];
                }
            }
        }
        while (cnt0 <= cnt1) {
            ++ cnt0;
            cost += que.top();
            que.pop();
        }
        chmin(ans, cost);
    }

    // output
    cout << ans << endl;
    return 0;
}
```
