---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_055_b/
  - /writeup/algo/atcoder/arc-055-b/
  - /blog/2017/10/23/arc-055-b/
date: "2017-10-23T17:13:58+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "probability", "dp" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc055/tasks/arc055_b" ]
---

# AtCoder Regular Contest 055: B - せんべい

hamkoさんが苦しんでて楽しそうだった: <https://docs.google.com/document/d/19z-mgAde_D_Xtom_dShy4ggrhzSWxGnNnoZ9T4jT6tU/edit>。なので解いた。
非独立である部分に気付かず私も苦しんだ。kmjpさんの[解説](http://kmjp.hatenablog.jp/entry/2016/06/04/0900)を見た。

## solution

確率DP。$\mathrm{dp} : (N + 1) \times (K + 1) \to [0, 1]$。$O(NK)$。

既に$i$個見て$j$個食べまだ$N$番目のせんべいは現れていないとし、その時点から最適に動いたときの$N$を食べられる確率を$\mathrm{dp}(i, j)$と定義する。
$i' \gt i$について既知と仮定し$\mathrm{dp}(i, j)$を考えよう。
$i = N$なら確率は$0$。
そうでないと仮定し$i$番目のせんべいを確認したとする。
新たに確認したせんべいが過去最高でなければ、明らかに食べる必要はない。
過去最高であれば、食べた場合と食べなかった場合で良い方を選べばよい。
食べた場合は$N$である確率と$N$でなくそれ以降で$N$を食べる確率の和、食べなかった場合は$N$でなくそれ以降で$N$を食べる確率の和がそれ。
ここまでに嘘はないが罠はあり、$N$である確率は過去最高である確率とは独立でない。
事象は次に$3$種に分類される。これに注意して書けば通る。

-   $N$である (自明に過去最高)
-   $N$ではないが過去最高
-   過去最高でない (自明に$N$でない)

## implementation

``` c++
#include <cmath>
#include <cstdio>
#include <functional>
#include <vector>
using namespace std;
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }

int main() {
    int n, k; scanf("%d%d", &n, &k);
    auto memo = vectors(n + 1, k + 1, NAN);
    function<double (int, int)> dp = [&](int i, int j) {
        if (not isnan(memo[i][j])) return memo[i][j];
        if (i == n or j == k) return memo[i][j] = 0;
        double is_n = 1.0 / (n - i);
        double fake = (1 - is_n) * (1.0 / (i + 1.0));
        double top = is_n + fake;
        return memo[i][j] =
            (1 - top) * dp(i + 1, j)
            + max(is_n + fake * dp(i + 1, j + 1),
                         fake * dp(i + 1, j));
    };
    printf("%.12lf\n", dp(0, 0));
    return 0;
}
```
