---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/473/
  - /blog/2016/12/25/yuki-473/
date: "2016-12-25T02:42:16+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp" ]
"target_url": [ "http://yukicoder.me/problems/no/473" ]
---

# Yukicoder No.473 和と積の和

問題文の撃墜に成功。
あっさり解けてしまいなぜ星$4$に昇格したのだろうという感じ。でもなんだか好きです。

## solution

演算の性質から適当にmemo化再帰で間に合う。計算量は分からないが$X$の対数ぐらいだろう。

$a \star b = a + b + ab$としよう。
この演算$\star$は結合法則を満たしかつ可換($(a \star b) \star c = a + b + c + ab + bc + ca + abc = a \star (b \star c)$)である。
逆演算を考えると$a \star b = x \iff b = \frac{x - a}{a + 1} \in \mathbb{N}$となる。
よって$S_1 \star S_2 \star \dots \star S_N = X$であるように広義単調増加な数列$S$を構成すればよく、
$S_1 \star \dots \star S\_{i-1}$まで決めたときに逆演算をして$S_i \star \dots \star S_N = Y$だけ考えればよい。つまり一種の動的計画法が使える。

さらにこの演算は急激に増える。$a \star a = a^2 + 2a = {(a + 1)}^2 - 1$であるので、乗算と同じくらい(ただし$a \ge 1$なので単位元は使えない)。
$S_i \star \dots \star S_N = Y$を作りたいときに(単調増加にとるので)$S_i \underbrace{\star S_i \star \dots \star S_i}\_{k \;\text{times}} \gt Y$で打ち切れば、これでかなりの枝刈りになって間に合う。


## implementation

``` c++
#include <iostream>
#include <map>
#include <tuple>
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
typedef long long ll;
using namespace std;
const int inf = 1e9+7;
int op(int a, int b) { // associative and commutative in N_+
    return min<ll>(inf, a + b + a*(ll)b);
}
int op_k(int a, int b, int k) { // a * b * b * ... * b  (k times)
    while (k -- and a != inf) a = op(a, b);
    return a;
}
ll solve(int n, int x, int last) {
    if (n == 1) {
        return (last <= x);
    } else {
        static map<tuple<int, int, int>, ll> memo;
        auto key = make_tuple(x, last, n);
        if (memo.count(key)) return memo[key];
        ll acc = 0;
        if (n == 0 and last <= x) acc += 1;
        repeat_from (a,last,x+1) {
            if (op_k(a, a, n-1) > x) break;
            if ((x - a) % (1 + a) == 0) {
                int b = (x - a) / (1 + a);
                if (a <= b) acc += solve(n-1, b, a);
            }
        }
        return memo[key] = acc;
    }
}
int main() {
    int n, x; cin >> n >> x;
    cout << solve(n, x, 1) << endl;
    return 0;
}
```
