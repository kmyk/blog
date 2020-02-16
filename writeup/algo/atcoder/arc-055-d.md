---
layout: post
redirect_from:
  - /blog/2017/05/26/arc-055-d/
date: "2017-05-26T05:11:48+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc055/tasks/arc055_d" ]
---

# AtCoder Regular Contest 055: D - 隠された等差数列

## solution

与えられた列$d$の差分列$\Delta(i) = d\_{i+1} - d\_i$をおく。

まず自明な場合を落としておく。
列$d$の長さが$1$なら$(A, B, X) = (d\_0, 0, 1)$。
集合$\\{ \Delta(i) \mid i \\}$がsingleton $\\{ \delta \\}$なら$(A, B, X) = (d\_0, \delta, 1)$。
この集合の要素数が$3$以上なら解は存在しない。
要素数が$2$でも$\\{ \delta\_0, \delta\_1 \\}$として$\delta\_0 + 1 \equiv \delta\_1 \pmod{10}$でなければ解は存在しない。
差分は基本的に$B$の$X$桁目$\delta\_0$と等しくかつ繰り上がりのあった場合のみそれに$+1$され$\delta\_1$になるため、このふたつ以外がでてくることはない。

結果の列の$X$桁目より上の部分は一意に決定できる。
まず$A, B$は高々$X$桁しかないとしてよい。それ以上あっても結果に影響しないため。
すると$X$桁目より真に上の部分は$X$桁目からの繰り上がりによってのみ増える。
初項$A = d\_0$が分かっており、繰り上がりは$d\_{i+1} \lt d\_i$であるときに発生しているので、これにより用意に求まる。
ただし$(\delta\_0, \delta\_1) = (9, 0) \equiv (9, 10) \pmod{10}$のときは$d\_{i+1} = d\_i$でも繰り上がりしている。
こうして求めた列を$e$とする。
性質としては$e\_i \cdot 10^{X-1} \le A + B \cdot i \lt (e\_i + 1) \cdot 10^{X-1}$ for all $i$であり、これを満たすことが$(A, B, X)$が解のひとつであることに必要十分。
この$e$は$X$に依存しない。

この制約 $e\_i \cdot 10^{X-1} \le A + B \cdot i \lt (e\_i + 1) \cdot 10^{X-1}$ for all $i$ について。
これはつまり直線$A + B \cdot i$がすべての線分$(i, e\_i \cdot 10^{X-1}) - (i, (e\_i + 1) \cdot 10^{X-1})$と交わるということ。
線分は半開区間のようになっていることに注意。

$B,X$が決定できれば$A$が定まる。
$e\_i \cdot 10^{X-1} \le A + B \cdot i$を変形して$A = \max \\{ e\_i \cdot 10^{X-1} - B \cdot i \mid i \\}$とすればよいため。
またこの式より、($X$を固定した上で)$B$は(有効な範囲で)大きければ大きいほど$A$が小さくなる。

$X$はおいておくとして、傾き$B$の範囲を求めたい。
単純には、各線分の対をそれぞれ見て定まる範囲の共通部分である。
つまり$(e\_j - (e\_i + 1)) \cdot 10^{X-1} \lt B \lt ((e\_j + 1) - e\_i) \cdot 10^{X-1}$ for all $i \lt j$から求める。
これは各$X$についてそれぞれ別に立つ式であるが、
$B' = \frac{B}{10^{X-1}} \in \mathbb{R}$として$e\_j - (e\_i + 1 - \epsilon) \le B' \le (e\_j + 1 - \epsilon) - e\_i$ for all $i \lt j$という実数上の制約とすればまとめて求められる。
$\epsilon$は半開区間のようになっていることから。

こうして求まった実数上の区間を$[B\_l, B\_r]$とする。
$X$を固定すればこれに$10^{X-1}$して天井/床を取れば整数上の区間$[\lceil B\_l \cdot 10^{X-1} \rceil, \lfloor B\_r \cdot 10^{X-1} \rfloor]$となる。
傾き$B$は大きいほうがよいので、(この区間が非空なら)$B = \lfloor B\_r \cdot 10^{X-1} \rfloor$となる。
$X$を下から見ていって、そのような$B$が存在すれば$A$を求めて答えとすればよい。

誤差などで怪しいときは、上のように求めた$B$の上限の周囲を適当に試して条件を満たすものだけを採用すればよい。

## implementation

``` c++
#include <cstdio>
#include <cctype>
#include <cmath>
#include <vector>
#include <set>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= int(m); --(i))
using ll = long long;
using namespace std;
template <class T> inline void setmax(T & a, T const & b) { a = max(a, b); }
template <class T> inline void setmin(T & a, T const & b) { a = min(a, b); }

int solve(vector<int> const & d) {
    int n = d.size();
    if (n == 1) return d[0];
    assert (n >= 2);
    vector<int> delta(n-1);
    repeat (i,n-1) {
        delta[i] = (d[i+1] - d[i] + 10) % 10;
    }
    int k1, k2; {
        set<int> set_delta(delta.begin(), delta.end());
        if (set_delta.size() == 1) return d[0]; // A = d_i, B = 0, X = 1
        if (set_delta.size() >= 3) return -1; // impossible
        k1 = *set_delta.begin();
        k2 = *(++ set_delta.begin());
        if (k1 == 0 and k2 == 9) {
            swap(k1, k2);
        } else if (k2 != k1 + 1) {
            return -1; // impossible
        }
    }
    vector<int> e(n); {
        int acc = 0;
        e[0] = d[0];
        repeat (i,n-1) {
            if (d[i+1] < d[i]) {
                acc += 1; // overflow
            } else if (d[i+1] == d[i] and k1 == 9 and k2 == 0) {
                acc += 1; // overflow with 10
            }
            e[i+1] = acc * 10 + d[i+1];
        }
    }
    long double min_b_float = 0;
    long double max_b_float = INFINITY;
    repeat (j,n) {
        repeat (i,j) {
            constexpr long double eps = 1e-18;
            setmin(max_b_float, ((e[j] + 1 - eps) - e[i]) /(long double) (j - i));
            setmax(min_b_float, (e[j] - (e[i] + 1 - eps)) /(long double) (j - i));
        }
    }
    ll base = 1;
    for (int x = 0; x < 16; ++ x, base *= 10) {
        ll max_b = floorl(max_b_float * base);
        repeat_from_reverse (b, max(0ll, max_b-3), max_b+4) { // workaround
            ll a = 0;
            repeat (i,n) {
                setmax(a, e[i] * base - b * i);
            }
            bool is_valid = true;
            repeat (i,n) {
                if (not (e[i] * base <= a + b * i and a + b * i < (e[i] + 1) * base)) {
                    is_valid = false;
                    break;
                }
            }
            if (is_valid) {
                return a;
            }
        }
    }
    return -1;
}

int main() {
    vector<int> d;
    for (char c; scanf("%c", &c), isdigit(c); ) {
        d.push_back(c - '0');
    }
    int result = solve(d);
    printf("%d\n", result);
    return 0;
}
```
