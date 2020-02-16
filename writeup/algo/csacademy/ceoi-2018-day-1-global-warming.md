---
layout: post
date: 2018-08-15T03:53:39+09:00
tags: [ "competitive", "writeup", "csacademy", "dp", "lis", "longest-increasing-subsequence" ]
"target_url": [ "https://csacademy.com/contest/ceoi-2018-day-1/task/global-warming/" ]
redirect_from:
  - /writeup/algo/cs-academy/ceoi-2018-day-1-global-warming/
---

# CS Academy CEOI 2018 Day 1: Global Warming

## solution

LIS。
修正する区間$[l, r)$の右端$r = n$かつ修正する量$d = x$としてよい。
普通の$O(n \log n)$ LISのアルゴリズムの配列を2本持って上手くやる。
単純には$i$番目まで見て状態が$$j \in \{ (+d\text{してない}), (+d\text{してる間}), (+d\text{して止めた後}) \}$$のどれであるかから列の長さを$\mathrm{dp}(i, j)$としてDPしたいが、これと$O(n \log n)$ LISを上手く融合させる感じになる。
$O(n \log n)$。

修正の方法について。
$d \ge 0$とすると、$+d$を$l$で始めた後に$r$で取り止めると損をするだけで、かつ増やすならできるだけたくさん増やした方が得。
$d \le 0$の場合も同様だが、前半に$-x$するのは後半に$+x$するのと変わらない。
よって区間$[l, n)$に$+x$する場合だけ考えればよい。

普通の$O(n \log n)$ LISの過程で現われる配列を考え、これを2本持つ。
「長さ$j$の増加列を作ったときの末尾の要素の最小値」が配列$l$の$j$項目となる。
1本目$l_0$はそのままのもの、2本目$l_1$は全体$[0, n)$に$+x$した列に対するもの。
それぞれ伸ばしながら、都度1本目から2本目に切り替えるような処理をしてやる。
そのまま伸ばす操作のために $l_0, l_1$に$t_i, t_i + x$をそれぞれ付け加えた後に、$+ x$する境界の処理のために各点で $$l_1 \gets \max \{ l_0, l_1 \}$$ の処理をする。
後者をまったくそのままやると$O(n)$だが、必要な箇所だけ修正するようにすると$O(1)$であり、全体でも$O(n \log n)$。

## note

解法の説明が難しい。
正しいことは分かるけど不安。
この回のコンテストの問題の中で一番「直感」みたいなのを要求する気がする。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

int push(vector<ll> & l, ll x) {
    auto it = lower_bound(l.begin(), l.end(), x);
    if (it == l.end()) {
        l.push_back(x);
        return l.size() - 1;
    } else {
        *it = x;
        return it - l.begin();
    }
}

int solve(int n, ll x, vector<ll> const & t) {
    vector<ll> l0, l1;
    for (ll t_i : t) {
        push(l1, t_i + x);
        int j = push(l0, t_i);

        // l1 = max(l0, l1)
        while (l1.size() <= j) {
            l1.push_back(l0[l1.size()]);
        }
        chmax(l1[j], l0[j]);
    }
    return l1.size();
}

int main() {
    int n; ll x; cin >> n >> x;
    vector<ll> t(n);
    REP (i, n) cin >> t[i];
    cout << solve(n, x, t) << endl;
    return 0;
}
```
