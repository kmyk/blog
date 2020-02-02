---
layout: post
alias: "/blog/2017/04/25/agc-013-d/"
date: "2017-04-25T22:41:03+09:00"
title: "AtCoder Grand Contest 013: D - Piling Up"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc013/tasks/agc013_d" ]
---

## solution

状態遷移の経路の数でなくてその出力の数を数えるという点が難しい。出力に関するこの言及を上手く状態の言葉に落とす。DP。$O(NM)$。

ある出力を生む経路は複数存在する。経路の集合をその出力の等しさで割って同値類を作り、特にその代表元を上手く選びたい。
経路の初期状態での赤い積み木の数が最小となるようなものをそのそのような代表元とすると上手くいく。
特にそのような場合、経路中で赤い積み木の数が$0$になるような時刻が存在することが示せる。
ここから逆に、単純な経路の数のDPをして、経路中で一度以上赤い積み木の数が$0$になるような経路の総数を数えればこれはちょうど代表元の数を数えることに等しい。
これは$O(NM)$のDPなので解けた。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <array>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
int main() {
    int n, m; scanf("%d%d", &n, &m);
    vector<array<ll, 2> > cur(n+1); // (the current number of R, whether it has ever been 0) -> the number of paths
    vector<array<ll, 2> > prv(n+1);
    cur[0][true] = 1;
    repeat_from (i,1,n+1) cur[i][false] = 1;
    while (m --) {
        prv.swap(cur);
        repeat (i,n+1) repeat (p,2) cur[i][p] = 0;
        repeat (i,n+1) {
            repeat (p,2) {
                if (i >= 1) {
                    bool q = i == 1 ? true : p;
                    cur[i-1][q] += prv[i][p]; // R R
                    cur[i][q] += prv[i][p]; // R B
                }
                if (i <= n-1) {
                    cur[i+1][p] += prv[i][p]; // B B
                    cur[i][p] += prv[i][p]; // B R
                }
            }
        }
        cur[0][ true] += cur[0][false];
        cur[0][false] = 0;
        repeat (i,n+1) repeat (p,2) cur[i][p] %= mod;
    }
    ll result = 0;
    repeat (i,n+1) result += cur[i][true];
    result %= mod;
    printf("%lld\n", result);
    return 0;
}
```
