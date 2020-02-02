---
layout: post
alias: "/blog/2016/11/28/code-festival-2016-final-c/"
date: "2016-11-28T02:15:10+09:00"
title: "CODE FESTIVAL 2016 Final: C - Interpretation"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "graph" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-final-open/tasks/codefestival_2016_final_c" ]
---

## solution

人と言語で二部グラフを作って連結性判定。$O(N + M)$。

単純に全ての言語の対に辺を張ると辺数$\sum \frac{K_i (K_i-1)}{2}$で$O(N^2)$になる問題を回避すればよいということ。
なので各人$i$の母国語$L\_{i1}$と第$n$言語$L\_{in}$ ($n \ge 2$)と考え、母国語とそれ以外との間にだけ辺を張るでもよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<vector<int> > g(n + m);
    auto ixa = [&](int i) { return i; };
    auto ixb = [&](int i) { return n + i; };
    repeat (i,n) {
        int k; cin >> k;
        repeat (j,k) {
            int l; cin >> l; -- l;
            g[ixa(i)].push_back(ixb(l));
            g[ixb(l)].push_back(ixa(i));
        }
    }
    vector<bool> used(n + m);
    function<void (int)> go = [&](int i) {
        used[i] = true;
        for (int j : g[i]) if (not used[j]) go(j);
    };
    go(ixa(0));
    bool ans = true;
    repeat (i,n) if (not used[ixa(i)]) ans = false;
    cout << (ans ? "YES" : "NO") << endl;
    return 0;
}
```
