---
layout: post
date: 2018-08-11T02:12:03+09:00
tags: [ "competitive", "writeup", "atcoder", "agc", "sort", "greedy" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc025/tasks/agc025_c" ]
---

# AtCoder Grand Contest 025: C - Interval Game

## solution

整列して貪欲。$O(N \log N)$。

高橋君の移動が貪欲でよいのは明らか。
指定された区間内で最も近い点に移動する、つまりまったく移動しないか近い方の端点に移動するかのどちらかjのみ。

青木君の選択について。
区間の左端と右端に高橋君を振るように移動させるのがよい。
連続して左端に移動させるような提出をするなら、最初から最後の区間だけ提出しても同じであるため。
また、使わない区間があっても移動距離は減りはしない。
先に左端に振るか右端に振るかは両方試すとして、以下は左端から始めると仮定して話す。
右端からだと式の形は多少変わるが基本は同じ。
これにより次のような問題で言い換えられる:

>   相異なる $i_1, i_2, \dots, i_k \le N$ を制約 $0 \lt L _ {i_1} \gt R _ {i_2} \lt L _ {i_3} \gt R _ {i_4} \lt \dots$ を満たすように選んで目的関数 $(L _ {i_1} - 0) + (L _ {i_1} - R _ {i_2}) + (L _ {i_3} - R _ {i_2}) + (L _ {i_3} - R _ {i_4}) + \dots$を最大化せよ

目的関数を整理すると$2 \sum L _ {i _ {2j}} - 2 \sum R _ {i _ {2j + 1}}$。
$2$種の制約のことをひとまず忘れれば、長さ$k$について総当たりし$L, R$を整列して貪欲に使うのが最適。
ここで、制約に違反しているなら目的関数の値が答えより大きくならないことを言えば、制約をなかったことにしてしまえる。
不等式制約については違反すると悪化するのは明らか。
distinct制約についても(同じ区間の同じ端点を複数回使うのはだめだが)両方の端点を使うと悪化するのでこれもよい。
よって$L, R$を貪欲に使えば答えが求まる。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int n; cin >> n;
    vector<int> l(n), r(n);
    REP (i, n) cin >> l[i] >> r[i];

    // solve
    sort(l.rbegin(), l.rend());
    sort(ALL(r));
    ll acc = 0;
    ll t = 0;
    REP (i, n) {
        chmax(acc, t + l[i]);
        chmax(acc, t - r[i]);
        chmax(acc, t + l[i] - r[i]);
        t += l[i] - r[i];
    }

    // output
    cout << 2 * acc << endl;
    return 0;
}
```
