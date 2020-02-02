---
layout: post
alias: "/blog/2016/02/23/arc-046-b/"
title: "AtCoder Regular Contest 046 B - 石取り大作戦"
date: 2016-02-23T02:37:49+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "game", "experiment", "typical-problem" ]
---

典型的な実験ゲー。
もちろんnimではない。単一のimpartial gameだし。

## [B - 石取り大作戦](https://beta.atcoder.jp/contests/arc046/tasks/arc046_b)

### 解法

実験。

判断基準はだいたい以下のようなもの。

-   入力が十分大きいこと
    -   線形は無理
    -   対数はなさそう
-   出力が0/1であること
    -   規則性を見つけやすい
-   明らかに一方が有利であること
    -   $A \lt B$で$N$が十分大きいなら$B$側が必ず勝ちそう

### 実装

``` python
#!/usr/bin/env python3
n = int(input())
a, b = map(int,input().split())
if a < b:
    ans = n <= a
elif a > b:
    ans = True
else:
    ans = n % (a + 1) != 0
print(['Aoki','Takahashi'][ans])
```

#### 実験用

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
template <typename T>
ostream & operator << (ostream & output, vector<T> const & a) {
    repeat (i, int(a.size())) { if (i) output << ' '; output << a[i]; }
    return output;
}
int main() {
    ll n, a, b; cin >> n >> a >> b;
    assert (n < 100);
    ll l[2] = { a, b };
    vector<vector<bool> > dp(2, vector<bool>(n+1));
    repeat (i,n+1) {
        repeat (j,2) {
            repeat_from (k, max(0ll,i-l[j]), i) {
                if (not dp[j^1][k]) {
                    dp[j][i] = true;
                    break;
                }
            }
        }
    }
    cerr << n << endl;
    cerr << a << ' ' << b << endl;
    cerr << dp[0] << endl;
    cerr << dp[1] << endl;
    cout << (dp[0][n] ? "Takahashi" : "Aoki") << endl;
    return 0;
}
```
