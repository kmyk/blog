---
layout: post
redirect_from:
  - /blog/2017/03/24/srm-698-med/
date: "2017-03-24T18:55:34+09:00"
tags: [ "competitive", "writeup", "topcoder", "srm", "convex-hull" ]
"target_url": [ "https://community.topcoder.com/stat?c=problem_statement&pm=14357" ]
---

# TopCoder SRM 698 Div1 Medium: IntersectingConvexHull

見ためはやばそうだが解法を聞いてしまえば(理解できてなくても)実装は楽。
間違った認識のまま通してしまったので後から詰めた。
思い付けるかはかなり怪しいが。

## problem

$2$次元平面上の点の集合$S$が与えられる。
点の集合$s \subseteq S$に対し$\mathrm{CH}(s)$をその凸包となる多角形とする。
$\\# \\{ (s_1, s_2) \mid s_1 \subseteq S \land s_2 \subseteq S \land s_1 \cap s_2 = \emptyset \land \mathrm{CH}(s_1) \cap \mathrm{CH}(s_1) \ne \emptyset \\}$を$\bmod 10^9+7$で答えよ。

## solution

補集合を数える。ふたつの凸包が交わらないとは間に線が引けることであり、そのような線は$2$点選んでその両方を通るものだけ考えればよい。$O(N^3)$。

$\|s\| \le 2$なら$\mathrm{CH}(s) = \emptyset$なので、$\|s\| \ge 3$のみ考えることとする。
全体集合は愚直に数えられる。

$2$点$i, j$を通るような直線を証拠に交わらない凸包を考える。
ふたつの真に交わらない凸包の共通内接線は(円と同様に)ちょうど$2$本であり<sup>要出典</sup>、今回は$3$頂点が同一直線上には来ないのでそれぞれの凸包からひとつずつ頂点を通る。
つまり頂点対を全列挙すれば、各凸包対$(s_1, s_2)$のその$2$つある共通内接線を両方列挙できる。
共通内接線が固定されれば、その両側から適当に点を取ってくればよい。

注意として、以下のように細部が面倒。テストを通るまで適当に$2$や$2^{-1}$を掛けることもできる。

-   接線を構成するための頂点対$(u, v)$は$u \lt v$と$v \lt u$で同じものが$2$回
-   接線によるひとつの分割につき頂点$(u, v)$を$u \in s_1 \land v \in s_2$と$v \in s_1 \land u \in s_2$で$2$倍
-   凸包対$(s_1, s_2)$が条件を満たすなら凸包対$(s_2, s_1)$も条件を満たすので$2$倍
-   凸包対$(s_1, s_2)$は共通内接線を$2$つ持つ

## implementation

``` c++
#include <bits/stdc++.h>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
class IntersectingConvexHull { public: int count(vector<int> x, vector<int> y); };

constexpr int mod = 1e9+7;
int powmod(int x, int y) {
    assert (0 <= x and x < mod);
    assert (0 <= y);
    int z = 1;
    for (int i = 1; i <= y; i <<= 1) {
        if (y & i) z = z *(ll) x % mod;
        x = x *(ll) x % mod;
    }
    return z;
}
int inv(int x) {
    return powmod(x, mod-2);
}
int fact(int n) {
    static vector<int> memo(1,1);
    if (memo.size() <= n) {
        int l = memo.size();
        memo.resize(n+1);
        repeat_from (i,l,n+1) memo[i] = memo[i-1] *(ll) i % mod;
    }
    return memo[n];
}
int choose(int n, int r) { // O(n) at first time, otherwise O(1)
    if (n < r) return 0;
    r = min(r, n - r);
    return fact(n) *(ll) inv(fact(n-r)) % mod *(ll) inv(fact(r)) % mod;
}

int IntersectingConvexHull::count(vector<int> x, vector<int> y) {
    int n = x.size();
    ll cnt = 0;
    repeat (i,n) repeat (j,i) {
        int l = 0, r = 0;
        repeat (k,n) if (k != i and k != j) {
            int ay = y[j] - y[i];
            int ax = x[j] - x[i];
            int by = y[k] - y[i];
            int bx = x[k] - x[i];
            if (ax *(ll) by < ay *(ll) bx) {
                ++ l;
            } else {
                ++ r;
            }
        }
        int s1 = (powmod(2, l) - 1 - l + mod) % mod;
        int s2 = (powmod(2, r) - 1 - r + mod) % mod;
        cnt += s1 *(ll) s2 * 2 % mod;
    }
    cnt %= mod;
    ll total = 0;
    repeat_from (k1,3,n+1) {
        repeat_from (k2,3,n+1-k1) {
            total += choose(n, k1) *(ll) choose(n-k1, k2) % mod;
        }
    }
    total %= mod;
    return (total - cnt + mod) % mod;
}
```
