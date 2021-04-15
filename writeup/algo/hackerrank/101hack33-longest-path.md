---
layout: post
redirect_from:
  - /writeup/algo/hackerrank/101hack33-longest-path/
  - /blog/2016/01/21/hackerrank-101hack33-longest-path/
date: 2016-01-21T21:33:08+09:00
tags: [ "competitive", "writeup", "hackerrank", "tree", "diameter" ]
---

# Hackerrank 101 Hack Jan 2016 Longest Path

## [Longest Path](https://www.hackerrank.com/contests/101hack33/challenges/longest-path)

### 問題

木が与えられる。頂点は白黒に塗り分けられている。
黒い頂点のみからなる道で最長のものの長さを答えよ。

### 解法

黒い頂点による各連結成分について直径を取る。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
pair<int,int> dfs(int i, int p, vector<bool> const & c, vector<vector<int> > const & g) {
    int depth = 0;
    int z = i;
    for (int j : g[i]) if (j != p and c[j]) {
        int ndepth, nz; tie(ndepth, nz) = dfs(j, i, c, g);
        if (depth < ndepth) {
            depth = ndepth;
            z = nz;
        }
    }
    return { depth + 1, z };
}
void use(int i, vector<bool> & usable, vector<vector<int> > const & g) {
    usable[i] = false;
    for (int j : g[i]) if (usable[j]) use(j, usable, g);
}
int main() {
    int n; cin >> n;
    vector<bool> c(n); repeat (i,n) { int it; cin >> it; c[i] = it; }
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int j; cin >> j; -- j;
        g[i+1].push_back(j);
        g[j].push_back(i+1);
    }
    int ans = 0;
    repeat (i,n) if (c[i]) {
        int depth, j;
        tie(depth, j) = dfs(i, -1, c, g);
        tie(depth, j) = dfs(j, -1, c, g);
        ans = max(ans, depth);
        use(j, c, g);
    }
    cout << ans << endl;
    return 0;
}
```
