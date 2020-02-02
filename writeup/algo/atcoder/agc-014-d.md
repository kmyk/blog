---
layout: post
alias: "/blog/2017/05/07/agc-014-d/"
date: "2017-05-07T23:09:54+09:00"
title: "AtCoder Grand Contest 014: D - Black and White Tree"
tags: [ "competitive", "writeup", "atcoder", "agc", "tree", "complete-matching" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc014/tasks/agc014_d" ]
---

こういうの解けるようになりたい。

## solution

完全マッチングの存在と後手必勝が同値。$O(N)$。
証明はeditorial見て。

---

少なくとも、完全マッチングが存在するなら後手必勝の向きは自明。
逆方向も示せると言われればできるので、完全マッチングの発想がなかったのが敗因。
後手の動きを考えればそうなのだが、先手の動きばかり考えていた気がする。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;

vector<pair<int, int> > complete_matching_of_tree(vector<vector<int> > const & g) { // O(N)
    int n = g.size();
    vector<pair<int, int> > result;
    vector<bool> used(n);
    function<bool (int, int)> dfs = [&](int i, int p) {
        int unused = -1;
        for (int j : g[i]) if (j != p) {
            if (not dfs(j, i)) return false;
            if (not used[j]) {
                if (unused != -1) {
                    return false;
                }
                unused = j;
            }
        }
        if (unused != -1) {
            result.emplace_back(i, unused);
            used[i] = true;
            used[unused] = true;
        }
        return true;
    };
    const int root = 0;
    if (not dfs(root, -1) or not used[root]) {
        result.clear();
    }
    return result;
}

int main() {
    int n; scanf("%d", &n);
    vector<vector<int> > g(n);
    repeat (i,n-1) {
        int a, b; scanf("%d%d", &a, &b); -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<pair<int, int> > result = complete_matching_of_tree(g);
    printf("%s\n", result.empty() ? "First" : "Second");
    return 0;
}
```
