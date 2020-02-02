---
layout: post
title: "AtCoder Regular Contest 091: F - Strange Nim"
date: 2018-08-19T01:54:39+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "nim", "grundy", "game", "dp", "ad-hoc", "binary-search" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc091/tasks/arc091_d" ]
---

## solution

grundy数を実験からad-hocに求める。
計算量は$O(\min(A/K, K))$ つまり $O(\sqrt{A})$ を$N$回。

$N$個の不偏ゲームの和になっているのでそれぞれgrundy数を求めて足せばよい。
以下 $N = 1$ と仮定してgrundy数 $g _ K (A)$ を求める。

愚直DPは明らかで $$g _ K (x) = \mathrm{mex} \left\{ g _ K (x - d) \mid 1 \le d \le \lfloor x/K \rfloor \right\}$$ でよい。
規則性を期待して初手で実験(典型)すると $K \mid x$ なら $g _ K (x) = x/K \in \mathbb{N}$ が分かる。
$K \not\mid x$ のときについても何か良い性質を言いたいが、$K \mid x$ の場合が成り立つことを踏まえて観察すれば $K \not\mid x$ なら $$g _ K (x) = g _ K ( x - \lfloor x/K \rfloor - 1 )$$ が分かる。
これにより $K \mid x$ かどうかに応じて$2$本の式が立った。
しかしまだ単にこれを実行すると例えば $A = K - 1$ のような場合に $O(K)$ かかる。
これは $\lfloor x/K \rfloor$ の値が変わらない範囲を二分探索などでまとめて処理すれば $O(A/K \log A)$ あるいは $O(A/K)$ に落ちる。
これを投げればACする。

証明や計算量解析はeditorialを見て。

## note

解くだけなら600点ぐらいな気がするが、計算量解析を入れると900点で合ってるという印象です

## implementation

``` c++
#include <iostream>
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;

int grundy(int a, int k) {
    while (a % k != 0) {
        ll delta = a / k + 1;
        if ((a - delta) / k != a / k) {
            a -= delta;
        } else {
            REP_R (i, 30) {  // binary search
                ll na = a - (delta << i);
                if (na >= 0 and na / k == a / k) {
                    a = na;
                }
            }
        }
    }
    return a / k;
}

int main() {
    int n; cin >> n;
    int g = 0;
    while (n --) {
        int a, k; cin >> a >> k;
        g ^= grundy(a, k);
    }
    cout << (g ? "Takahashi" : "Aoki") << endl;
    return 0;
}
```
