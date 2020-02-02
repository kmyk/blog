---
layout: post
alias: "/blog/2017/12/31/arc-085-e/"
title: "AtCoder Regular Contest 085: E - MUL"
date: "2017-12-31T16:04:28+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "flow", "maximum-flow", "project-selection-problem" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc085/tasks/arc085_c" ]
---

## solution

最大流。project selection problemとか燃やす埋めると呼ばれるあれをすればよい。dinicだと速い$O(N^3 \log \log N)$のはず。

枝刈り全探索でも通るらしい。

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">Eはフローっぽさあるなぁと思ったが分からず．2^Nの枝刈りを書いてた．</p>&mdash; kuuso (@kuuso1) <a href="https://twitter.com/kuuso1/status/929343389358702592?ref_src=twsrc%5Etfw">2017年11月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">ん、これ最小カットなんですか(枝刈り探索で通してしまった)</p>&mdash; 競プロなりきられbot (@DEGwer3456) <a href="https://twitter.com/DEGwer3456/status/929343625539944448?ref_src=twsrc%5Etfw">2017年11月11日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


## implementation

``` c++
#include <cstdio>
#include <functional>
#include <queue>
#include <unordered_map>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;

constexpr ll inf = ll(1e18)+9;

uint64_t pack(int i, int j) {
    return (uint64_t(i) << 32) | j;
}
ll maximum_flow(int s, int t, int n, unordered_map<uint64_t, ll> & capacity /* adjacency matrix */) { // dinic, O(V^2E)
    auto residue = [&](int i, int j) { auto key = pack(i, j); return capacity.count(key) ? capacity[key] : 0; };
    vector<vector<int> > g(n); repeat (i,n) repeat (j,n) if (residue(i, j) or residue(j, i)) g[i].push_back(j); // adjacency list
    ll result = 0;
    while (true) {
        vector<int> level(n, -1); level[s] = 0;
        queue<int> q; q.push(s);
        for (int d = n; not q.empty() and level[q.front()] < d; ) {
            int i = q.front(); q.pop();
            if (i == t) d = level[i];
            for (int j : g[i]) if (level[j] == -1 and residue(i,j) > 0) {
                level[j] = level[i] + 1;
                q.push(j);
            }
        }
        vector<bool> finished(n);
        function<ll (int, ll)> augmenting_path = [&](int i, ll cur) -> ll {
            if (i == t or cur == 0) return cur;
            if (finished[i]) return 0;
            finished[i] = true;
            for (int j : g[i]) if (level[i] < level[j]) {
                ll f = augmenting_path(j, min(cur, residue(i,j)));
                if (f > 0) {
                    capacity[pack(i, j)] -= f;
                    capacity[pack(j, i)] += f;
                    finished[i] = false;
                    return f;
                }
            }
            return 0;
        };
        bool cont = false;
        while (true) {
            ll f = augmenting_path(s, inf);
            if (f == 0) break;
            result += f;
            cont = true;
        }
        if (not cont) break;
    }
    return result;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    // solve
    const int src = n;
    const int dst = n + 1;
    unordered_map<uint64_t, ll> capacity;
    ll sum_positive = 0;
    repeat (i, n) {
        if (a[i] > 0) {  // positive
            sum_positive += a[i];
            capacity[pack(src, i)] = a[i];
        } else if (a[i] < 0) {  // negative
            capacity[pack(i, dst)] = - a[i];
            repeat (j, n) if (a[j] > 0) {  // positive
                if ((j + 1) % (i + 1) == 0) {
                    capacity[pack(j, i)] = inf;
                }
            }
        }
    }
    ll result = sum_positive - maximum_flow(src, dst, n + 2, capacity);
    // output
    printf("%lld\n", result);
    return 0;
}
```
