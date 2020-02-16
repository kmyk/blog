---
layout: post
alias: "/blog/2016/12/06/ddcc-2016-final-d/"
date: "2016-12-06T13:32:19+09:00"
tags: [ "competitive", "writeup", "ddcc", "atcoder" ]
"target_url": [ "https://beta.atcoder.jp/contests/ddcc2016-final/tasks/ddcc_2016_final_d" ]
---

# DISCO presents ディスカバリーチャンネル コードコンテスト2016 本戦: D - シャツの部屋

私は気付かずだったが、「初日はTシャツを買いにいくためのTシャツがないのでは」「そもそもTシャツは貰うものでは」といった点が指摘されていた。

## solution

大部分を最も効率のよいTシャツを使い細かい部分はDP。$O({(\max A_i)}^3)$。
$O(NM)$のDPでは明らかに間に合わない。

まず、洗濯回数$w$は$0 \le w \lt A_i$としてよい。
Tシャツは初日に全て買うとしてかまわないこと、まだ着れる服が残っているなら洗濯する必要がないことから言える。

洗濯回数$w$を固定する。
$M \le 10^9$と大きいので、最も効率のよいTシャツ$i = \operatorname{argmax}\_i \frac{B_i}{\min \\{ w+1, A_i \\}}$を繰り返し使うことになる。

最も効率のよいTシャツ$i$以外のTシャツを使う回数を考える。$A\_{\mathrm{eff}} = \min \\{ w+1, A_i \\}$とする。
Tシャツを$k$枚買ってそれぞれ$a_j = \min \\{ w+1, A\_{i_j} \\}$ ($j \lt k$)回使ったとする。
順に使って累積和のようにすると$s_j = \sum\_{k \lt j} a_k$と書け、もし$k \gt A\_{\mathrm{eff}}$であれば$s_j \equiv s_k \pmod{A\_{\mathrm{eff}}}$な$j,k$がある。
この$j \lt k$に関して、$j, j+1, \dots, k-1$番目のTシャツを使った回数は$A\_{\mathrm{eff}}$の整数倍であり、最も効率のよいTシャツで置き換えてよい。
これにより枚数$k \le A\_{\mathrm{eff}}$である。

最も効率のよいTシャツ以外の部分の費用について。
枚数$k$の議論より、使用回数は${(\max A_i)}^2$で抑えられる。
$O(N {(\max A_i)}^2)$のDPができるが、しかしこれを各$w$にすると間に合わない。
よってDP tableの部分更新をする。
$w$を増やすたびに、$w+1$回使えるTシャツ$i$で最も安いもの($A_i \ge w+1$)に関して$O({(\max A_i)}^2)$で更新すればよい。
ただし$w+1 \lt A_i$なTシャツでも$w+1$回のみ着ることができるので、Tシャツに関して前処理をして、$\max A_i$個のTシャツとして整理しておく。
よって全体で$O({(\max A_i)}^3)$となる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmin(T & a, T const & b) { if (b < a) a = b; }
const ll inf = ll(1e18)+9;
int main() {
    int n; ll m, c; cin >> n >> m >> c;
    vector<int> a(n); vector<ll> b(n); repeat (i,n) cin >> a[i] >> b[i];
    const int a_max = *whole(max_element, a);
    ll ans = inf;
    vector<ll> dp(pow(a_max+3, 2), inf);
    dp[0] = 0;
    repeat (w, a_max) { // the number of washing
        ll step = inf;
        int best_a = 1; ll best_b = inf;
        repeat (i,n) {
            if (w+1 <= a[i]) setmin(step, b[i]);
            int cand_a = min(w+1, a[i]); ll cand_b = b[i];
            if (cand_b/(double)cand_a < best_b/(double)best_a) {
                best_a = cand_a;
                best_b = cand_b;
            }
        }
        repeat (t,dp.size()) {
            if (dp.size() <= t + w+1) break;
            setmin(dp[t + w+1], dp[t] + step);
        }
        ll k = max<ll>(0, (m -(ll) dp.size()) / best_a + 1);
        setmin(ans, c*w + k*best_b + dp[m-k*best_a]);
    }
    cout << ans << endl;
    return 0;
}
```
