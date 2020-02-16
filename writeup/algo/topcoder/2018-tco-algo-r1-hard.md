---
layout: post
alias: "/blog/2018/04/22/2018-tco-algo-r1-hard/"
date: "2018-04-22T02:57:56+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "tco", "dijkstra" ]
---

# 2018 TCO Algorithm: Hard. Deadfish

## solution

Dijkstra。小さくする方向にはdecrementしかないため頂点数は$N + 1$個とみなせる。$O(N \log N)$。

## note

-   ところでこれBFSで十分ですね。頭が付いてない
-   `REP_R (d, 10) { ... }` とすべきところを `REP_R (d, 9) { ... }` として落とした。頭が付いてない

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using namespace std;
template <class T> using reversed_priority_queue = priority_queue<T, vector<T>, greater<T> >;
template <class T> inline void chmin(T & a, T const & b) { a = min(a, b); }
class Deadfish { public: int shortestCode(int N); };

int p_operation(int x) {
    int cnt[10] = {};
    while (x) {
        cnt[x % 10] += 1;
        x /= 10;
    }
    int y = 0;
    REP_R (d, 10) {
        while (cnt[d] --) {
            y = y * 10 + d;
        }
    }
    return y;
}

int Deadfish::shortestCode(int N) {
    vector<int> dist(N + 1, INT_MAX);
    reversed_priority_queue<pair<int, int> > que;
    dist[0] = 0;
    que.emplace(dist[0], 0);
    while (not que.empty()) {
        int dist_i; int i; tie(dist_i, i) = que.top(); que.pop();
        if (dist[i] < dist_i) continue;
        if (i == N) break;
        vector<long long> js;
        js.push_back(i + 1);
        js.push_back(i - 1);
        js.push_back(i * (long long)i);
        js.push_back(p_operation(i));
        for (long long j : js) {
            if (j < 0) continue;
            if (N < j) {
                if (j < 1e9 + 7) {
                    chmin<int>(dist[N], dist[i] + 1 + (j - N));
                }
                continue;
            }
            if (dist_i + 1 < dist[j]) {
                dist[j] = dist_i + 1;
                que.emplace(dist[j], j);
            }
        }
    }
    return dist[N];
}
```
