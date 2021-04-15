---
redirect_from:
  - /writeup/algo/codeforces/1037-d/
layout: post
date: 2018-09-03T01:53:00+09:00
tags: [ "competitive", "writeup", "codeforces", "bfs" ]
"target_url": [ "http://codeforces.com/contest/1037/problem/D" ]
---

# Manthan, Codefest 18 (rated, Div. 1 + Div. 2): D. Valid BFS?

## 解法

列$a$をちらみしながら実際にBFSしてみる。
$O(N \log N)$。

BFSをするときの曖昧性は問題文中の(4.)の順序のみであるが、ここをどう決めるべきかは列$a$から一意に定まる。
この情報を好きな方法で取得しそれに沿ってBFSしてみて結果が一致するか確かめればよい。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

bool solve(int n, vector<vector<int> > const & g, vector<int> const & a) {
    queue<int> que;
    vector<bool> used(n);
    que.emplace(0);
    used[0] = true;

    if (a[0] != 0) return false;
    int i = 1;
    while (not que.empty()) {
        int x = que.front();
        que.pop();

        vector<int> children = g[x];
        children.erase(remove_if(ALL(children), [&](int y) { return used[y]; }), children.end());
        sort(ALL(children));
        vector<int> sliced(a.begin() + i, a.begin() + i + children.size());
        sort(ALL(sliced));
        if (children != sliced) return false;

        REP (j, children.size()) {
            que.emplace(a[i]);
            used[a[i]] = true;
            ++ i;
        }
    }
    return true;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int x, y; scanf("%d%d", &x, &y);
        -- x;
        -- y;
        g[x].push_back(y);
        g[y].push_back(x);
    }
    vector<int> a(n);
    REP (i, n) {
        scanf("%d", &a[i]);
        -- a[i];
    }

    // solve
    bool answer = solve(n, g, a);

    // output
    printf("%s\n", answer ? "Yes" : "No");
    return 0;
}
```
