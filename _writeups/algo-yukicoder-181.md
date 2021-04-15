---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/181/
  - /blog/2017/01/03/yuki-181/
date: "2017-01-03T15:01:42+09:00"
tags: [ "competitive", "writeup", "yukicoder", "periodicity" ]
"target_url": [ "http://yukicoder.me/problems/no/181" ]
---

# Yukicoder No.181 A↑↑N mod M

法$M$依存の周期性というのは即見えたのにだめだった。

## solution

法$M$による周期性。多めに見積もって$O(M^2)$ぐらい。

tetrationの定義は
$$ a \uparrow\uparrow n = \begin{cases}
    1 & (n = 0) \\\\
    a^{a \uparrow\uparrow n-1} & (\text{otherwise})
\end{cases} $$である。
定義に従っては計算できないので、$M$で剰余を取りながら計算したい。

一般に、いい感じの関数$f$に対する$f(n) \bmod M$は周期性を持ち、特に$n \ge A_f$以降で周期$B_f$を持つという形になる。
つまり$$ i(n) = \begin{cases}
    n & (n \le A_f) \\\\
    ((n - A_f) \bmod B_f) + A_f & (n \ge A_f)
\end{cases} $$という関数$i$を用いて$f(n) \bmod M = f(i(n)) \bmod M$。
羃$a^n$はこのような周期性を持つ。

$f(a,n,m) = a \uparrow\uparrow n \bmod m$を求めよう。
定義から
$$ f(a, n, m) = \begin{cases}
    1 & (n = 0) \\\\
    a^{a \uparrow\uparrow n-1} \bmod m & (n \ge 1)
\end{cases} $$であり、$a^n \bmod m$の周期を上で書いた$(A_m, B_m)$としてその周期性の手前かその中かで場合分けし、
$$ f(a, n, m) = \begin{cases}
    1 & (n = 0) \\\\
    a^{a \uparrow\uparrow n-1} \bmod m & (n \ge 1 \land a \uparrow\uparrow n-1 \le A_m) \\\\
    a^{A_mB_m + f(a, n-1, B_m)} \bmod m & (n \ge 1 \land a \uparrow\uparrow n-1 \ge A_m)
\end{cases} $$とする。
未だ$a \uparrow\uparrow n-1$が残っているが、条件部を$3$項述語$a \uparrow\uparrow n-1 \le A_m$として処理すれば、$A_m$より大きい値は出てこないので計算できる。
$m = 1$や$a = 0, 1$の場合に面倒が発生するので、事前に除いておくとよい。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <map>
#include <functional>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using ll = long long;
using namespace std;
struct sequence {
    vector<int> data;
    int offset, cycle;
};
sequence iterate(int a, function<int (int)> f) {
    sequence xs;
    map<int, int> used;
    while (not used.count(a)) {
        used[a] = xs.data.size();
        xs.data.push_back(a);
        a = f(a);
    }
    xs.offset  = used[a];
    xs.cycle = xs.data.size() - xs.offset;
    return xs;
}
int at(sequence const & xs, int i) {
    return xs.data[i < xs.offset ? i : (i - xs.offset) % xs.cycle + xs.offset];
}
double tet(int a, int n) {
    double acc = 1;
    repeat (i,n) {
        acc = pow(a, acc);
        if (isinf(acc)) break;
    }
    return acc;
}
int tetmod(int a, int n, int m) {
    if (m == 1) return 0;
    if (n == 0) return 1;
    if (a == 0) return 0;
    if (a == 1) return 1;
    double estimated = tet(a, n-1);
    sequence powmod = iterate(1, [&](int x) { return a *(ll) x % m; });
    ll b = tetmod(a, n-1, powmod.cycle);
    int i = estimated < powmod.offset ? estimated : b + powmod.offset * powmod.cycle;
    return at(powmod, i);
}
int main() {
    int a, n, m; cin >> a >> n >> m;
    cout << tetmod(a, n, m) << endl;
    return 0;
}
```
