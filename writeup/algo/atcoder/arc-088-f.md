---
layout: post
alias: "/blog/2018/01/04/arc-088-f/"
title: "AtCoder Regular Contest 088: F - Christmas Tree"
date: "2018-01-04T12:22:40+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp", "tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc088/tasks/arc088_d" ]
---

やれば解けた。

## solution

$A$を適当に求める。その上で木DPと二分探索で$B$を定める。$O(N (\log N)^2)$。

$A$について。
ある種の最小path被覆になっている。
とりあえず根からできるだけ長いpathを伸ばす。
根から降りていってある頂点$v$を見たとき、まだ被覆されていない頂点を子に持つならばその数だけpathを下向きに生やす。下向きに生やしたpathを$k$本とすると、対にして頂点$v$で繋いでひとつにできるので$A$は$\mathrm{ceil}(\frac{k}{2})$だけ増える。

$B$について。
仮にこれを固定し実際に木を被覆できるかで二分探索をする。
各部分木についてそれを被覆したとき根から上にどれだけの長さのpathが余るかで木DP。
例えばちょうどふたつの頂点からなる木を被覆したとき、その根においては長さが$B - 1$余っている。
入力例$1$の木で頂点$1$を根で$B = 4$としたとき、$7 - 6 - 4 - 5$と$4 - 2 -3$と$2 - 1 - \ast - \ast$の$3$本のpathで被覆できて長さは$2$余る。
その計算は、子の部分木で余る長さを集めてきて$O(k \log k)$かけて適当に対を作り消せばよい。
同時にいくつのpathが生成されたかを数えておけば全体が判定できる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
using namespace std;

template <typename UnaryPredicate>
int binsearch(int l, int r, UnaryPredicate p) {
    assert (l <= r);
    -- l;
    while (r - l > 1) {
        int m = l + (r - l) / 2;  // avoid overflow
        (p(m) ? r : l) = m;
    }
    return r;
}

int main() {
    // input
    int n; scanf("%d", &n);
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int a, b; scanf("%d%d", &a, &b);
        -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    // solve
    constexpr int root = 0;
    int a = 0; {
        vector<char> used(n);
        function<void (int, int)> use_chain = [&](int i, int parent) {
            used[i] = true;
            for (int j : g[i]) if (j != parent and not used[j]) {
                use_chain(j, i);
                break;
            }
        };
        function<void (int, int)> go = [&](int i, int parent) {
            int count_not_used = 0;
            for (int j : g[i]) if (j != parent) {
                if (not used[j]) {
                    count_not_used += 1;
                    use_chain(j, i);
                }
                go(j, i);
            }
            a += (count_not_used + 1) / 2;
        };
        go(root, -1);
    }
    int b = binsearch(1, n, [&](int b) {
        int count_chain = 0;
        function<int (int, int)> go = [&](int i, int parent) {
            map<int, int> chain;
            for (int j : g[i]) if (j != parent) {
                int length = go(j, i);
                if (length - 1 >= 1) {
                    chain[length - 1] += 1;
                }
            }
            for (auto it = chain.begin(); it != chain.end(); ) {
                // pop
                int length, count; tie(length, count) = *it;
                chain[length] = 0;
                // make pairs
                while (count) {
                    it = chain.lower_bound(b - length);
                    if (it == chain.end()) break;
                    if (it->first == length) {
                        assert (it->second == 0);
                        count_chain -= count / 2;
                        count %= 2;
                    } else {
                        int delta = min(count, it->second);
                        count_chain -= delta;
                        count -= delta;
                        it->second -= delta;
                    }
                    if (not it->second) {
                        chain.erase(it);
                    }
                }
                // write back
                if (count) {
                    chain[length] = count;
                } else {
                    chain.erase(length);
                }
                // increment
                it = chain.lower_bound(length + 1);
            }
            if (chain.empty()) {
                if (i == root) {
                    return -1;
                } else {
                    count_chain += 1;
                    return b;
                }
            } else {
                return chain.rbegin()->first;
            }
        };
        go(root, -1);
        return count_chain <= a;
    });
    // output
    printf("%d %d\n", a, b);
    return 0;
}
```
