---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/243/
  - /blog/2016/08/26/yuki-243/
date: "2016-08-26T01:16:47+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "inclusion-exclusion-principle" ]
"target_url": [ "http://yukicoder.me/problems/no/243" ]
---

# Yukicoder No.243 出席番号(2)

解けず。解説を見た。包除原理は苦手らしい。

包除原理+DP。
この問題の何が難しいかというと、割り振る出席番号$j$か生徒ごとの嫌いな数$A_i$かのどちらかで順に処理していきたいが、そのような良い方法が見つからない、両方をDPの引数にして$\mathrm{dp} : N \times N \to \mathbb{N}$などができない。
なので、だめな割り振り方に着目し、包除原理でななめに潰して$\mathrm{dp} : \|A\| \to \mathbb{N}$にしている。


``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
typedef long long ll;
using namespace std;
const int mod = 1e9+7;
int main() {
    // input
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    // prepare
    vector<ll> fact(n+1);
    fact[0] = 1;
    repeat (i,n) fact[i+1] = fact[i] * (i+1) % mod;
    // compute
    vector<int> cnt(n);
    repeat (i,n) {
        if (a[i] < n) {
            cnt[a[i]] += 1;
        }
    }
    vector<ll> dp(n+1);
    dp[0] = 1;
    repeat (i,n) if (cnt[i]) {
        repeat_reverse (k,n) {
            dp[k+1] += dp[k] * cnt[i] % mod;
            dp[k+1] %= mod;
        }
    }
    ll ans = fact[n];
    repeat (k,n) {
        ans += dp[k+1] * fact[n-(k+1)] % mod * ((k+1) % 2 == 1 ? -1 : 1) % mod;
        ans %= mod;
    }
    ans += mod;
    ans %= mod;
    // output
    cout << ans << endl;
    return 0;
}
```
