---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-exhibition-b/
  - /blog/2016/12/13/code-festival-2016-exhibition-b/
date: "2016-12-13T02:16:23+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-exhibition-open/tasks/codefestival_2016_ex_b" ]
---

# CODE FESTIVAL 2016 Exhibition: B - Exact Payment

解法を聞いてしまえば、何故あまり解かれなかったのか不思議に感じてしまう。
円と他の図形との衝突判定の、円の厚みを他方に押し付けて点との衝突判定にするテクっぽさがある。

結局乱択が何故落ちるかは分からずのままだった。

## solution

$O(2^N)$のDPを逆転させ、区間の集合を値とするDP。硬貨が$d$羃のとき$O(d^2 N \log \max A_i)$。

まず、硬貨ごとに分けて考えてよい。
さらに、$10^k$円の硬貨が$d$枚必要となるのは、ある$X \subset \\{ A_i \mid 1 \le i \le N \\}$があって$\sum X$の$10$進数展開の$10^k$の桁の数字が$d$以上であるとき。
つまり、$k$桁目を$d$以上にする和の存在を判定できればよい。

単純に判定するとすると$2^N$通りの足し方を確認せねばならず間に合わない。
高速に判定したい。
特にちょうど$d$であるか判定するとすると、判定条件$\sum X \in [d \cdot 10^k, (d+1) \cdot 10^k)$となる。
これを変形すると$0 \in [d \cdot 10^k - \sum X, (d+1) \cdot 10^k - \sum X)$と書ける。
そこで、区間$[d \cdot 10^k, (d+1) \cdot 10^k)$から始めて各$A_i$を引いていき、$0$を含むようにできるかを考えるとする。
一見これも$2^N$個の区間ができるように見えるが、区間$[d \cdot 10^k, (d+1) \cdot 10^k)$は全区間の$\frac{1}{10}$であるため、適切に併合すれば$10$個で抑えられる。
こうなれば$O(N)$で計算できる。
引きすぎて区間$[l,r)$が$r \le 0$となる場合等が存在し注意は必要だが、適当にすれば通る。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from_reverse(i,m,n) for (int i = (n)-1; (i) >= int(m); --(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
struct interval_t { ll l, r; };
bool operator < (interval_t a, interval_t b) { return make_pair(a.l, a.r) < make_pair(b.l, b.r); }
bool is_mergeable(interval_t a, interval_t b) { return not (a.r <= b.l or b.r <= a.l); }
interval_t merge(interval_t a, interval_t b) { assert (is_mergeable(a, b)); return { min(a.l, b.l), max(a.r, b.r) }; }
interval_t shift(interval_t a, ll b) { return { a.l - b, a.r - b }; }
interval_t modulo(interval_t a, ll b) { ll l = (a.l % b + b) % b; return { l, a.r + (l - a.l) }; }
bool does_include(interval_t a, ll b) { return a.l <= b and b < a.r; }
int main() {
    int n; cin >> n;
    vector<ll> as(n); repeat (i,n) cin >> as[i];
    int ans = 0;
    for (ll e = 1; e <= ll(1e17); e *= 10) {
        repeat_from_reverse (d,1,10) {
            vector<interval_t> xs;
            xs.push_back({ d*e, (d+1)*e });
            for (ll a : as) {
                vector<interval_t> ys = xs;
                for (interval_t x : xs) {
                    ys.push_back(       shift(x, a % (10*e)));
                    ys.push_back(modulo(shift(x, a % (10*e)), 10*e));
                }
                xs.clear();
                whole(sort, ys);
                for (interval_t y : ys) {
                    if (y.r <= 0) continue;
                    if (xs.empty() or not is_mergeable(xs.back(), y)) {
                        xs.push_back(y);
                    } else {
                        xs.back() = merge(xs.back(), y);
                    }
                }
            }
            bool found = false;
            for (interval_t x : xs) if (does_include(x, 0)) found = true;
            if (found) { ans += d; break; }
        }
    }
    cout << ans << endl;
    return 0;
}
```
