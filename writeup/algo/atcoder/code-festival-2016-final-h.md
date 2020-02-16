---
layout: post
alias: "/blog/2016/12/24/code-festival-2016-final-h/"
date: "2016-12-24T22:43:53+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "dp", "game" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-final-open/tasks/codefestival_2016_final_h" ]
---

# CODE FESTIVAL 2016 Final: H - Tokaido

本番では部分点まで。$x \gets \|x - a_i\|$を繰り返してるなあというのまでは気付いていたが、その先をするには頭も時間も足りてなかった。
明らかに怪しい$\sum A_i$制約を部分点実装してる間に忘れてしまったのも一因のように思う。

## solution

DPを変形して整理してから再度DPに落とす。$O(\sum A_i)$で前処理して$O(M)$。

$M = 1$のための愚直なDPを書いて整理すると以下のようになる。

$$ \begin{array}{lll}
A_n & = X \\\\
\mathrm{dp}\_X(n-1) & = 0 \\\\
\mathrm{dp}\_X(i) & = \|\mathrm{dp}\_X(i+1) - A\_{i+2}\| & (1 \le i \le n-2) \\\\
\mathrm{ans}   & = \mathrm{dp}\_X(1) + A_1 - A_2
\end{array} $$

この関数を逆から計算する。
$\mathrm{dp'}\_X(n) = \mathrm{dp}\_X(1)$になるような$\mathrm{dp'}$を考える。
数列$A$を$A_3, A_4, \dots, A_i$までに制限したときの$\mathrm{dp}\_X(1)$を$\mathrm{dp'}\_X(i)$とすると

$$ \begin{array}{lll}
\mathrm{dp'}\_X(3) & = X \\\\
\mathrm{dp'}\_X(i+1) & = \mathrm{dp'}\_{\|X - A_i\|}(i) & (3 \le i \le n-1)
\end{array} $$

また、絶対値の性質から$X \ge \sum\_{3 \le i \le n-1} A_i$と$X$が十分大きいとき$\mathrm{dp}\_X(0) = X - \sum\_{3 \le i \le n-1} A_i$。
よって$X \lt \sum\_{3 \le i \le n-1} A_i$と仮定してよい。

$\mathrm{dp'}\_X(i+1) = \mathrm{dp'}\_{\|X - A_i\|}(i)$という取り方により、$\mathrm{dp'}\_{A_i \pm k}(i+1) = \mathrm{dp'}\_k(i)$と言える。
ここから

$$ \begin{array}{lll}
\mathrm{dp'}\_X(i+1) & = \mathrm{dp'}\_{X - A_i}(i) & (X \ge A_i) \\\\
\mathrm{dp'}\_X(i+1) & = \mathrm{dp'}\_{A_i - X}(i) & (X \lt A_i)
\end{array} $$

であり、これは$\mathrm{dp'}\_X(i)$の$X$に関して前から$A_i-1$個を逆順にして先頭に加えたもの。
これをdequeに対して愚直に行えば$\sum A_i \le 10^6$の制約により間に合う。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <deque>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;

int main() {
    int n; cin >> n;
    vector<int> a(n-1); repeat (i,n-1) cin >> a[i];
    int sum_a = accumulate(a.begin()+2, a.end(), 0);
    deque<int> dp(sum_a+1); whole(iota, dp, 0);
    repeat_from (i,2,n-1) {
        repeat (j,a[i]) dp.push_front(dp[2*j+1]);
    }
    int m; cin >> m;
    while (m --) {
        int x; cin >> x;
        cout << (x < dp.size() ? dp[x] : x - sum_a) + a[0] - a[1] << endl;
    }
    return 0;
}
```
