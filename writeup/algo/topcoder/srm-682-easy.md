---
layout: post
redirect_from:
  - /blog/2016/02/23/srm-682-easy/
date: 2016-02-23T12:24:05+09:00
tags: [ "competitive", "writeup", "topcoder", "srm", "graph" ]
---

# TopCoder SRM 682 Div1 Easy: SmilesTheFriendshipUnicorn

何かあるのかなと思って時間を溶かした結果、特に何もなかった。

## [Easy: SmilesTheFriendshipUnicorn]()

### 問題

連結グラフが与えられる。長さ$4$の道$P_5$の存在を判定せよ。

### 解法

単に各点からdfsすればよい。

### 実装

``` c++
#include <bits/stdc++.h>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
class SmilesTheFriendshipUnicorn { public: string hasFriendshipChain(int N, vector<int> A, vector<int> B); };
string SmilesTheFriendshipUnicorn::hasFriendshipChain(int n, vector<int> a, vector<int> b) {
    vector<vector<int> > g(n);
    repeat (i, a.size()) {
        g[a[i]].push_back(b[i]);
        g[b[i]].push_back(a[i]);
    }
    vector<int> used;
    function<bool (int)> dfs = [&](int i) {
        used.push_back(i);
        if (5 <= used.size()) return true;
        for (int j : g[i]) {
            if (not count(used.begin(), used.end(), j)) {
                if (dfs(j)) return true;
            }
        }
        used.pop_back();
        return false;
    };
    bool ans = false;
    repeat (i,n) {
        if (dfs(i)) { ans = true; break; }
    }
    return ans ? "Yay!" : ":(";
}
```
