---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/269/
  - /blog/2016/10/21/yuki-269/
date: "2016-10-21T16:08:07+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp" ]
"target_url": [ "http://yukicoder.me/problems/no/269" ]
---

# Yukicoder No.269 見栄っ張りの募金活動

調和数$H_n = \Sigma\_{k = 1}^n \frac{1}{k}$と自然対数$\log x = \int_1^x\frac{dt}{t}$の関連性を始めて認識した。増加速度は同じでよさそう(未証明)。

## solution

DP。$O((S - K^2)\log N)$。

$a_0 + (a_0 + a_1 + K) + (a_0 + a_1 + a_2 + 2K) + \dots + (a_0 + a_1 + a_2 + \dots + a\_{n-1} + (n-1)K) = S$ な $a_0, a_1, a_2, \dots, a\_{n-1} \in \mathbb{N}$ を数える問題。
制約は整理すると$Na_0 + (N-1)a_1 + (N-2)a_2 + \dots + a\_{n-1} = S - K \frac{(N-1)N}{2}$である。
これをDPする。
各$a_i$の範囲はおよそ$0 \le a_i \le \frac{S}{N-i}$であることから、調和級数の和は発散するとはいえ、$N \le 100$なので高々$\Sigma\_{1 \le k \le N}\frac{1}{k} \approx 5$であり間に合う。

## implementation

``` c++
#include <iostream>
#include <vector>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
using namespace std;
const int mod = 1e9+7;
int main() {
    int n, s, k; cin >> n >> s >> k;
    s -= k * (n-1)*n/2;
    if (s < 0) {
        cout << 0 << endl;
    } else {
        vector<int> dp(s+1);
        dp[0] = 1;
        repeat (i,n) {
            repeat_reverse (j,s+1) {
                for (int a = 1; j + a*(n-i) < s+1; ++ a) {
                    dp[j + a*(n-i)] += dp[j];
                    dp[j + a*(n-i)] %= mod;
                }
            }
        }
        cout << dp[s] << endl;
    }
    return 0;
}
```
