---
layout: post
alias: "/blog/2016/02/25/utpc-2013-i/"
title: "東京大学プログラミングコンテスト2013 I - 支配と友好"
date: 2016-02-25T06:48:14+09:00
tags: [ "competitive", "writeup", "codefestival" ]
---

なんとなく、こどふぇすの動画([続・ペアプログラミング](https://www.youtube.com/watch?v=jotn1-RzOC0))を見て、一緒に書いた。

## [I - 支配と友好](https://beta.atcoder.jp/contests/utpc2013/tasks/utpc2013_09)

### 解説

<https://www.youtube.com/watch?v=jotn1-RzOC0>を見よう。

euler tourで説明されているが、グラフを平面描画して左側と右側に分けてそれぞれ求めている、とも言える。
そもそもeuler tourと平面描画ってちょっと似てる気もする。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#include <functional>
#include <climits>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
template <typename T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<vector<int> > g(n), rev(n);
    repeat (i,n-1) {
        int s, t; cin >> s >> t;
        g[  s].push_back(t);
        rev[t].push_back(s);
    }
    int root; repeat (i,n) if (rev[i].size() == 0) root = i;
    vector<vector<int> > cands(n);
    set<int> vs;
    function<void (int, int)> dfs = [&](int i, int p) {
        auto it = vs.upper_bound(a[i]);
        if (it == vs.end()) {
            if (not vs.empty()) cands[i].push_back(* vs.rbegin());
        } else {
            cands[i].push_back(* it);
            if (it != vs.begin()) cands[i].push_back(* -- it);
        }
        for (int j : g[i]) if (j != p) dfs(j, i);
        vs.insert(a[i]);
    };
    dfs(root, -1);
    repeat (i,n) reverse(g[i].begin(), g[i].end());
    vs.clear();
    dfs(root, -1);
    repeat (i,n) {
        pair<int,int> ans = { INT_MAX, -1 };
        for (int cand : cands[i]) {
            setmin(ans, make_pair(abs(cand - a[i]), cand));
        }
        cout << ans.second << endl;
    }
    return 0;
}
```
