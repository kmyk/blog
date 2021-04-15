---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_016_d/
  - /writeup/algo/atcoder/agc-016-d/
  - /blog/2017/10/03/agc-016-d/
date: "2017-10-03T05:15:04+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "xor" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc016/tasks/agc016_d" ]
---

# AtCoder Grand Contest 016: D - XOR Replace

## solution

式を見るとswapしかできないことが分かる。$O(N)$。

総和$A = \sum a\_i$のとき$a\_j' = A$と操作すると総和は$A' = (A \oplus a\_j) \oplus A = a\_j$と更新される。
つまりレジスタ$A$とメモリ$a\_1, \dots, a\_N$の間でのxchg操作のみができる。
$A, a\_1, \dots, a\_N$で$b\_1, \dots, b\_N$をカバーできていなければ自明に不可能、そうでなければ可能。

レジスタを用いたswap操作による並べ替えの操作回数を最小化する問題に帰着された。
これは(直接的にswapできると見做して)入れ換えたい位置同士に辺を張ってグラフを作り、その連結成分ごとに処理していくように考えればできる。
ただしレジスタの初期値を上手く使うことができることには注意。

## implementation

``` c++
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <functional>
#include <map>
#include <numeric>
#include <set>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define whole(x) begin(x), end(x)
using namespace std;

int solve(int n, vector<int> const & a, vector<int> const & b) {
    int sum_a = accumulate(whole(a), 0, bit_xor<int>());
    {
        map<int, int> cnt;
        for (int a_i : a) {
            cnt[a_i] += 1;
        }
        cnt[sum_a] += 1;
        for (int b_i : b) {
            if (cnt.count(b_i)) {
                cnt[b_i] -= 1;
                if (cnt[b_i] == 0) {
                    cnt.erase(b_i);
                }
            }
        }
        assert (not cnt.empty());
        if (cnt.size() >= 2 or cnt.begin()->second >= 2) {
            return -1;  // impossible
        }
    }
    int mismatch = 0;
    int component = 0; {
        map<int, set<int> > g;
        repeat (i, n) {
            if (a[i] != b[i]) {
                mismatch += 1;
                g[b[i]].insert(a[i]);
            }
        }
        set<int> used;
        function<void (int)> go = [&](int a_i) {
            used.insert(a_i);
            for (int a_j : g[a_i]) if (not used.count(a_j)) {
                go(a_j);
            }
        };
        component += 1;
        if (g.count(sum_a)) {
            go(sum_a);
        }
        repeat (i, n) if (not used.count(a[i])) {
            if (g.count(a[i])) {
                component += 1;
                go(a[i]);
            }
        }
    }
    return mismatch + (component - 1);
}

int main() {
    int n; scanf("%d", &n);
    vector<int> a(n); repeat (i, n) scanf("%d", &a[i]);
    vector<int> b(n); repeat (i, n) scanf("%d", &b[i]);
    int result = solve(n, a, b);
    printf("%d\n", result);
    return 0;
}
```
