---
layout: post
date: 2018-12-07T02:09:01+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc084/tasks/arc084_c" ]
redirect_from:
  - /writeup/algo/atcoder/arc_084_e/
  - /writeup/algo/atcoder/arc-084-e/
---

# AtCoder Regular Contest 084: E - Finite Encyclopedia of Integer Sequences

## 解法

### 概要

$$K$$ の偶奇で場合分け。
$$O(N)$$。

### 詳細

$$K$$ が偶数だとしよう。
先頭が $$1, 2, \dots, K/2$$ の整数列は $$X/2$$ 個存在し、先頭が $$K/2 + 1, K/2 + 2, \dots, K$$ の整数列は $$X/2$$ 個存在する。
よって求めるのは先頭が $$K/2$$ の整数列の中で最も大きいもの。
つまり $$(K/2, K, K, K, \dots, K)$$ の形。

$$K$$ が奇数だとしよう。
先頭が $$1, 2, \dots, \lfloor K/2 \rfloor$$ の整数列と先頭が $$\lfloor K/2 \rfloor + 2, \lfloor K/2 \rfloor + 3, \dots, K$$ の整数列はちょうど同数存在する。
よって $$X/2$$ 番目の整数列の先頭は $$\lfloor K/2 \rfloor + 1$$ と分かる。
基本はこれを繰り返して $$f = (\lfloor K/2 \rfloor + 1, \lfloor K/2 \rfloor + 1, \lfloor K/2 \rfloor + 1, \dots, \lfloor K/2 \rfloor + 1)$$ という列である。
しかし $$2$$ 段目以降は $$(\lfloor K/2 \rfloor + 1), (\lfloor K/2 \rfloor + 1, \lfloor K/2 \rfloor + 1), \dots$$ という列の影響ですこしずつずれる。
よってこのずれの分で $$\lfloor N/2 \rfloor$$ 回だけ $$f$$ をdecrementする必要がある。
decrement部分はならし $$O(1)$$ なので間に合う。


## メモ

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using namespace std;

vector<int> solve(int k, int n) {
    if (k == 1 and n == 1) {
        return vector<int>(1, 1);

    } else if (k % 2 == 0) {
        // the last sequence starting with k / 2
        vector<int> a(n, k);
        a[0] = k / 2;
        return a;

    } else {
        // basically the sequence whose all elements are k / 2 + 1
        vector<int> a(n, k / 2 + 1);
        REP (i, n / 2) {
            // decrement
            if (a.back() >= 2) {
                -- a.back();
                while (a.size() < n) {
                    a.push_back(k);
                }
            } else {
                a.pop_back();
            }
        }
        return a;
    }
}

int main() {
    int k, n; cin >> k >> n;
    auto a = solve(k, n);
    for (int a_i : a) {
        cout << a_i << ' ';
    }
    cout << endl;
    return 0;
}
```
