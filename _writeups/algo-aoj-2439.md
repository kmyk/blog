---
layout: post
redirect_from:
  - /writeup/algo/aoj/2439/
  - /blog/2016/07/14/aoj-2439/
date: "2016-07-14T18:18:14+09:00"
tags: [ "competitive", "writeup", "aoj", "dp" ]
"target_url": [ "http://judge.u-aizu.ac.jp/onlinejudge/description.jsp?id=2439" ]
---

# AOJ 2439. Hakone

さすがICPC・JAG非公式難易度表でたくさん星付いてるだけあって、良い問題だった。

<!-- more -->

## solution

上から順に見ていくDP。$O(N^3)$。

順位変動がない$c_k = \mathrm{-}$の走者に関して、これは無視できる。
つまり全ての走者は順位変動を起こすとしてよい。

区間$A = [0,k)$までを見て、この区間$X$での遷移の状況を決定することを考える。
すると区間$B = (k,n)$に対し、元々$B$に居た人が$A$に移動するような遷移$B \to A$あるいはその逆$A \to B$のような遷移に関して決定できないまま残る。
しかしこのような遷移の数を$i,j$とおいて併せて持つことにより、その区間での遷移の状況を決定できる。
つまり、区間$A = [0,k)$に対し、区間$B = (k,n)$として$B \to A$の遷移の数$i$と$A \to B$の遷移の数$j$とを決めると、そのような状況下での元々のありえた通過順の数が計算できる。
これはDPで全ての$i,j,k$に関して計算でき、答えが求まる。

## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
const int mod = 1e9+7;
int main() {
    int n; scanf("%d", &n);
    vector<char> s(n); repeat (i,n) scanf(" %c", &s[i]);
    vector<vector<ll> > cur(n+1, vector<ll>(n+1)); // dp : (requiring-up) \times (dangling-down) \to (count)
    vector<vector<ll> > prv(n+1, vector<ll>(n+1));
    cur[0][0] = 1;
    for (char c : s) {
        cur.swap(prv);
        repeat (i,n+1) repeat (j,n+1) {
            if (c == '-') {
                cur[i][j] = prv[i][j];
            } else if (c == 'U') {
                cur[i][j] = 0;
                ;                          cur[i][j] += prv[i][j] * i; // up
                if (i-1 >= 0 and j-1 >= 0) cur[i][j] += prv[i-1][j-1]; // down
                cur[i][j] %= mod;
            } else if (c == 'D') {
                cur[i][j] = 0;
                if (i+1 < n+1 and j+1 < n+1) cur[i][j] += prv[i+1][j+1] * (i+1) * (j+1); // up
                ;                            cur[i][j] += prv[i][j] * j; // down
                cur[i][j] %= mod;
            }
        }
    }
    printf("%lld\n", cur[0][0]);
    return 0;
}
```
