---
layout: post
redirect_from:
  - /writeup/algo/atcoder/cf17-final-g/
  - /blog/2017/11/26/cf17-final-g/
date: "2017-11-26T10:02:32+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "game", "dp", "linerity" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf17-final-open/tasks/cf17_final_g" ]
---

# CODE FESTIVAL 2017 Final: G - Mancala

D以上で一番簡単だと思います(ギャップが小さい気がする)。

## solution

線形性。上手く状態を潰して後ろからDP。$O(N^4)$。

始めに列$a$に対するゲームのスコアの最小値$f(a)$の計算を考えよう。
これは「その時点で操作できる最小の$i$について操作する」を繰り返すのが最適。
これは以下の考察などから言える:

-   操作ごとに石の数は常にちょうど$1$減少するので、操作回数の最大化と考えてよい
-   マス$i$で一度$a\_i \gt i$になると、そのマスはそれ以降なにも操作できない
-   マス$i$での操作は下側(つまり$j \lt i$なマス$j$)にのみ影響する

これを高速に計算し足し合わせたい。足すだけなので線形で、上手く状態を潰してDPをすれば端から順に処理していけそうに見える。
上から順にマス$i$まで見てそれより上で$j$回操作したような状態を考え、そのような状態の個数を$\mathrm{dp}(i, j)$とする。
これは$O(N \times N^2)$ぐらいの表。
最終的な答えを求めるには、マス$i$ごとに別個に、最終的に残る石の数の総和を足し込んでいく。
$a\_i$と$j'$を固定すればマス$i$での最終的に残る石の数が求まり、下側はどうしようとこれに影響しないので$\mathrm{dp}(i + 1, j')$だけ見ればマス$i$の影響する分が定まる。


## implementation

``` c++
#include <cstdio>
#include <vector>
#define repeat(i, n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i, m, n) for (int i = (m); (i) < int(n); ++(i))
#define repeat_reverse(i, n) for (int i = (n)-1; (i) >= 0; --(i))
using ll = long long;
using namespace std;

constexpr int mod = 1e9+7;
int main() {
    int n, k; scanf("%d%d", &n, &k);
    const int dp_size = n * n + 3;
    vector<ll> cur(dp_size);
    cur[0] = 1;
    ll result = 0;
    repeat_reverse (i, n) {
        vector<ll> prv = move(cur);
        cur.assign(dp_size, 0);
        ll nxt = 1; repeat (j, i) nxt = nxt * (k + 1) % mod;
        repeat (a_i, min(k, i + 1) + 1) {
            repeat (delta, dp_size) if (prv[delta]) {
                result += (a_i + delta) % (i + 1) * nxt % mod * prv[delta] % mod;
                cur[delta + (a_i + delta) / (i + 1)] += prv[delta];
            }
        }
        repeat_from (a_i, (i + 1) + 1, k + 1) {
            repeat (delta, dp_size) if (prv[delta]) {
                result += (a_i + delta) * nxt % mod * prv[delta] % mod;
                cur[delta] += prv[delta];
            }
        }
        repeat (delta, dp_size) if (cur[delta]) {
            cur[delta] %= mod;
        }
        result %= mod;
    }
    printf("%lld\n", result);
    return 0;
}
```
