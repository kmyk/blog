---
layout: post
redirect_from:
  - /blog/2016/03/27/tco-2016-round-1a-hard/
date: 2016-03-27T04:17:15+09:00
tags: [ "competitive", "writeup", "topcoder", "tco", "tree", "graph", "greedy" ]
---

# TopCoderOpen 2016 round 1A Hard: EllysTree

本番解けず。2時間のコンテストだったら解けたかも。

## 問題

根付き木が与えられる。
根から出発し、現在いる頂点の先祖または子孫に移動することを繰り返す。
既に訪問した頂点には移動できない。
このようにして全ての頂点を巡ることは可能か。
可能なら可能な訪問順の中で、辞書順最小のものを答えよ。

## 解法

貪欲 $\times$ 貪欲。$O(N^3)$。

いくらか頂点を使った状態$S$から次に頂点$v$を使って(最小性以外の)条件を満たす訪問が可能かどうかを表す述語$\phi_S(v)$を考える。これが$O(N)$であれば、全体は$O(N^3)$となる。小さい頂点から貪欲に選べばよい。

$\phi_S(v)$は貪欲に頂点を使用していけばよい。
移動可能な頂点の中で最も深い位置にあるものを適当に選び続ける。
適当なcacheを行えば$O(N)$になる。

## 実装

``` c++
#include <bits/stdc++.h>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
template <class T> bool setmin(T & l, T const & r) { if (not (r < l)) return false; l = r; return true; }
using namespace std;
class EllysTree { public: vector<int> getMoves(vector<int> parent); };
vector<int> EllysTree::getMoves(vector<int> a_parent) {
    int n = a_parent.size() + 1;
    auto parent = [&](int i) { return a_parent[i-1]; };
    vector<vector<int> > children(n);
    repeat_from (i,1,n) children[parent(i)].push_back(i);
    auto usable = [&](int i, vector<bool> used, int cnt) {
        used[i] = true;
        ++ cnt;
        vector<int> iter(n);
        function<int (int)> find_leaf = [&](int i) {
            for (int & j = iter[i]; j < children[i].size(); ++ j) {
                int leaf = find_leaf(children[i][j]);
                if (leaf != -1) return leaf;
            }
            if (not used[i]) return i;
            return -1;
        };
        function<int (int)> find_parent = [&](int i) {
            while (used[i]) {
                if (i == 0) return -1;
                i = parent(i);
            }
            return i;
        };
        while (true) {
            int j = -1;
            if (j == -1) j = find_leaf(i);
            if (j == -1) j = find_parent(i);
            if (j == -1) break;
            used[j] = true;
            ++ cnt;
            i = j;
        }
        return cnt == n;
    };
    vector<vector<bool> > desc(n, vector<bool>(n)); {
        repeat_from (i,1,n) desc[parent(i)][i] = true;
        repeat (k,n) {
            repeat (i,n) {
                repeat (j,n) {
                    if (desc[i][k] and desc[k][j]) {
                        desc[i][j] = true;
                    }
                }
            }
        }
    }
    vector<int> ans; {
        vector<bool> used(n);
        int cnt = 0;
        int i = 0;
        used[i] = true;
        ++ cnt;
        while (true) {
            int k = n; // next
            repeat (j,n) if (desc[i][j] or desc[j][i]) {
                if (not used[j] and usable(j, used, cnt)) {
                    setmin(k, j);
                }
            }
            if (k == n) break;
            used[k] = true;
            ans.push_back(k);
            ++ cnt;
            i = k;
        };
        if (cnt != n) ans.clear();
    }
    return ans;
}
```
