---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_001_e/
  - /writeup/algo/atcoder/agc-001-e/
  - /blog/2017/04/27/agc-001-e/
date: "2017-04-27T18:41:12+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc001/tasks/agc001_e" ]
---

# AtCoder Grand Contest 001: E - BBQ Hard

頭がいい感じの解法。imos法っぽい。

## solution

DPで組み合せ求めるやつを同じ表でまとめてやる。
$H = \max\_i A_i, \; W = \max\_i B_i$として$O(HW)$。

愚直にやると答えは$\sum\_{j \lt N} \sum\_{i \lt j} {A\_i + B\_i + A\_j + B\_j}\_{}C\_{A\_i + A\_j}$。
しかしこれを単純に求めると$O(N^2)$になってしまう。
${}\_NC\_R$を求める方法のひとつとして格子上の経路数として説明されるDPが知られている。
この経路の始点を複数にして同時にやる。
$[- \max\_i A_i, + \max\_i A_i] \times [- \max\_i B_i, + \max\_i B_i]$の表を用意して、それぞれの$i$について$(A_i, B_i)$に$1$を置くことで初期化とし、この上で同様な更新をする。
その後それぞれの$i$について$(A_i, B_i)$の位置の値を足し合わせ、同じ串を$2$回使ってしまう分を引き、串の使用順序を無視するため$2$で割れば答え。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

constexpr int mod = 1e9+7;
int main() {
    // input
    int n; scanf("%d", &n);
    vector<int> a(n), b(n); repeat (i,n) scanf("%d%d", &a[i], &b[i]);
    // dp
    int max_a = *whole(max_element, a);
    int max_b = *whole(max_element, b);
    vector<vector<int> > choose = vectors(2*max_a+1, 2*max_b+1, int());
    choose[0][0] = 1;
    vector<vector<int> > dp = vectors(2*max_a+1, 2*max_b+1, int());
    repeat (i,n) {
        dp[max_a-a[i]][max_b-b[i]] += 1;
    }
    repeat (y,2*max_a+1) {
        repeat (x,2*max_b+1) {
            choose[y][x] %= mod;
            dp[y][x] %= mod;
            if (y+1 < 2*max_a+1) choose[y+1][x] += choose[y][x];
            if (x+1 < 2*max_b+1) choose[y][x+1] += choose[y][x];
            if (y+1 < 2*max_a+1) dp[y+1][x] += dp[y][x];
            if (x+1 < 2*max_b+1) dp[y][x+1] += dp[y][x];
        }
    }
    // result
    ll result = 0;
    repeat (i,n) {
        result += dp[max_a+a[i]][max_b+b[i]];
        result -= choose[2*a[i]][2*b[i]];
    }
    result %= mod;
    result *= (mod+1)/2; // inv(2, mod)
    result %= mod;
    if (result < 0) result += mod;
    // output
    printf("%lld\n", result);
    return 0;
}
```
