---
redirect_from:
  - /writeup/algo/atcoder/qupc-2018-f/
layout: post
date: 2018-10-25T14:09:57+09:00
tags: [ "competitive", "writeup", "atcoder", "qupc", "bit-dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/qupc2018/tasks/qupc2018_f" ]
---

# 九州大学プログラミングコンテスト2018: F - Team Making

## 解法

### 概要

bit-DP。先頭にのみ追加する感じで重複を回避。$O(2^N N^2)$。

### 詳細

制約は $O(2^N N^3)$ のbit-DPを考えろて言っている。
しかし単純にやると、チームの決定の順序が考慮されてしまい重複が発生する。
そこでチームを埋める順番を一意にしてやる。
例えば、チームメンバーの中で添字が一番大きいものをリーダーとし、リーダーの添字の順で追加してやればよい。
チームの集合に対しその構成順序が唯一なので重複なく数えられる。

## メモ

-   $O(2^N N^3)$ で実装してしまったがよく見たら `i` が$1$通りなので自明に $O(2^N N^2)$ にできる

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

ll solve(int N, int K, vector<int> const & a) {
    vector<ll> dp(1 << N);
    dp[0] = 1;
    REP3 (s, 1, 1 << N) {
        REP (i, N) if ((s & (1 << i)) and (s ^ (1 << i)) < (1 << i)) {
            dp[s] += dp[s ^ (1 << i)];
            REP (j, i) if (s & (1 << j)) {
                if (a[i] + a[j] <= 2 * K) {
                    dp[s] += dp[s ^ (1 << i) ^ (1 << j)];
                }
                REP (k, j) if (s & (1 << k)) {
                    if (a[i] + a[j] + a[k] <= 3 * K) {
                        dp[s] += dp[s ^ (1 << i) ^ (1 << j) ^ (1 << k)];
                    }
                }
            }
        }
    }
    return dp.back();
}

int main() {
    int n, k; cin >> n >> k;
    vector<int> a(n);
    REP (i, n) cin >> a[i];
    cout << solve(n, k, a) << endl;
    return 0;
}
```
