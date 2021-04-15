---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_057_b/
  - /writeup/algo/atcoder/arc-057-b/
  - /blog/2016/07/10/arc-057-b/
date: "2016-07-10T15:36:23+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc057/tasks/arc057_b" ]
---

# AtCoder Regular Contest 057 B - 高橋君ゲーム

本番では、下限だけでなく上限も丁寧にDPして、下限と上限の間は全て実行可能であるとしてこれを未証明のまま投げて一発ACした。
通ったからよいけど、すごくだめな感じがする。

## solution

DP。$i$日目までに$j$回勝率が上昇するときの勝利回数の下限$\mathrm{dp}\_{i,j}$を求める。$O(N^2)$。

合計の勝利回数$K$の制約がないとき、$0$日目で$a_0 - 1$回勝ってそれ以降の$n+1$日目に$a\_{n+1}$回勝つのが最適。
$a_0 \le 1$か否かに応じて$N$または$N-1$回勝率が上昇する。

合計の勝利回数$K$の制約を考慮しよう。
上を踏まえると、$j$回勝率が上昇するのに合計で$L \lt K$回勝利する列から、$j$回以上勝率が上昇しちょうど$K$回勝利する列を構成できる。
遅い日から順に勝利回数を貪欲に増加させればよい。
ただし例外があって、$K = \Sigma a_i$であるとき、これは上昇回数が必ず$1$であるという自明な結果に潰れるので注意する。

あとは下限の計算方法である。これはDP。
$i+1$日目で$j+1$回上昇するときの勝利回数の下限は、既に$j+1$回上昇している状態から全部負ける場合と$j$回上昇している場合から最小限勝つ場合から計算でき、$\mathrm{dp}\_{i+1,j+1} = \min \\{ \mathrm{dp}\_{i,j+1}, \mathrm{dp}\_{i,j} + \delta \\}$。
ただし$\mathrm{dp}\_{i,j} + \delta = \min \\{ d \le a_i \mid \frac{\mathrm{dp}\_{i,j}}{\Sigma\_{l \lt i} a_l} \lt \frac{d}{\Sigma\_{l \lt i+1} a_l} \\}$である。$\delta$は簡単な式変形で求まるが、定義されない場合があるので注意。

## implementation

``` c++
#include <cstdio>
#include <vector>
#include <algorithm>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_reverse(i,n) for (int i = (n)-1; (i) >= 0; --(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const int infty = 1e9+7;
int main() {
    // input
    int n, k; scanf("%d%d", &n, &k);
    vector<int> a(n); repeat (i,n) scanf("%d", &a[i]);
    // compute
    vector<int> acc(n+1); whole(partial_sum, a, acc.begin()+1);
    vector<int> dp(n+1, infty);
    dp[0] = 0;
    repeat (i,n) {
        repeat_reverse (j,n) {
            if (dp[j] != infty) {
                int delta = acc[i] == 0 ? 1 : (dp[j] *(ll) acc[i+1] / acc[i] + 1 - dp[j]);
                if (delta <= a[i]) {
                    setmin(dp[j+1], dp[j] + delta);
                }
            }
        }
    }
    // output
    int ans = 0;
    if (acc[n] == k) {
        ans = 1;
    } else {
        repeat (j,n+1) {
            if (dp[j] <= k) {
                ans = j;
            }
        }
    }
    printf("%d\n", ans);
    return 0;
}
```
