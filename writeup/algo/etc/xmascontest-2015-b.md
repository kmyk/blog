---
layout: post
redirect_from:
  - /blog/2015/12/24/xmascontest-2015-b/
date: 2015-12-24T22:55:20+09:00
tags: [ "competitive", "writeup", "atcoder", "dfs" ]
---

# Xmas Contest 2015 B - Broken Christmas Tree

## [B - Broken Christmas Tree](https://beta.atcoder.jp/contests/xmascontest2015/tasks/xmascontest2015_b) {#b}

変なdfsを投げてみたら通った。
計算量がどうなっているのかは分からない。

### 実装

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
void dfs(int i, set<int> & notused, vector<set<int> > const & forbidden, vector<pair<int,int> > & result) {
    vector<int> use;
    for (int j : notused) {
        if (not forbidden[i].count(j)) {
            use.push_back(j);
        }
    }
    for (int j : use) {
        notused.erase(j);
        result.emplace_back(i,j);
    }
    for (int j : use) dfs(j, notused, forbidden, result);
}
int main() {
    int n, m; cin >> n >> m;
    vector<set<int> > forbidden(n);
    repeat (i,m) {
        int p, q; cin >> p >> q;
        -- p; -- q;
        forbidden[p].insert(q);
        forbidden[q].insert(p);
    }
    set<int> notused; repeat (i,n) notused.insert(i);
    vector<pair<int,int> > result;
    notused.erase(0);
    dfs(0, notused, forbidden, result);
    if (result.size() == n-1) {
        cout << "Yes" << endl;
        for (auto p : result) cout << p.first+1 << ' ' << p.second+1 << endl;
    } else {
        cout << "No" << endl;
    }
    return 0;
}
```
