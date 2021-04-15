---
layout: post
redirect_from:
  - /writeup/algo/atcoder/jag2016-domestic2-e/
  - /blog/2016/06/12/jag2016-domestic2-e/
date: 2016-06-12T22:30:47+09:00
tags: [ "competitive", "writeup", "icpc", "jag", "dp", "bit-dp" ]
"target_url": [ "http://acm-icpc.aitea.net/index.php?2016%2FPractice%2F%E6%A8%A1%E6%93%AC%E5%9B%BD%E5%86%85%E4%BA%88%E9%81%B8B" ]
---

# JAG 模擬国内予選 2016: E - ぼくのかんがえたさいきょうのおふとん

なんとか通して$5$完の$12$位。やったね。

途中までは貪欲+乱択で無理矢理通そうとしていたが、それは無理でした。

## problem

For given $s \in \mathbb{N}^n, d \in \mathbb{N}^m$, answer $\min\_\sigma \min_k \Sigma\_{j \lt m} \| d_j - \Sigma\_{i \lt k_j} \sigma(s)\_i \|$.

## solution

DP。
$d$を昇順にすると、おふとんをおしいれに戻す操作が発生しなくなり、これまでに追加したおふとんの順番が無視できる。
$d$をsortしておいて$d_j$まで見て、これまでに$s$の$x \subseteq \\{ 1, \dots, n \\}$番目を使ったときの、不快度の最小値$\operatorname{dp}\_{j,x}$を求める。$O(MN2^N)$。

$\operatorname{dp}\_{j,x} = (\min\_{y \subseteq x} \operatorname{dp}\_{j-1,y}) + \| d_j - \Sigma\_{i \in x} s_i \|$という更新。
$\operatorname{dp}\_{j,x}$を、$x$の中にまだ使ってないものがあってもよいとして緩めて適当にすると実装が楽。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
int main() {
    while (true) {
        int n, m; cin >> n >> m;
        if (n == 0 and m == 0) break;
        vector<int> s(n); repeat (i,n) cin >> s[i];
        vector<int> d(m); repeat (i,m) cin >> d[i];
        sort(d.begin(), d.end());
        vector<int> acc(1<<n);
        repeat (x,1<<n) {
            repeat (i,n) if (x & (1<<i)) {
                acc[x] += s[i];
            }
        }
        vector<vector<int> > dp(m+1, vector<int>(1<<n));
        repeat (j,m) {
            repeat (x,1<<n) {
                dp[j+1][x] = dp[j][x] + abs(d[j] - acc[x]);
                repeat (i,n) if (x & (1<<i)) {
                    int y = x & ~ (1<<i);
                    dp[j+1][x] = min(dp[j+1][x], dp[j+1][y]);
                }
            }
        }
        cout << dp[m][(1<<n)-1] << endl;
    }
    return 0;
}
```
