---
layout: post
redirect_from:
  - /writeup/algo/atcoder/arc_088_e/
  - /writeup/algo/atcoder/arc-088-e/
  - /blog/2018/01/04/arc-088-e/
date: "2018-01-04T20:13:11+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "segment-tree", "shakutori-method" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc088/tasks/arc088_c" ]
---

# AtCoder Regular Contest 088: E - Papple Sort

想定解はもう少しかしこげでした。

## solution

両端から順に削っていくのを高速にやる。
文字列長$N = \|S\|$と文字種$L = 26$を使って$O(N (L + \log N))$。
segment木で妥協せず丁寧に実装すれば$O(LN)$にできるはず。

両端から順に削っていくことを考える。
両端の文字が同じならそのまま削れる。
両端が異なるなら、左端と同じ種類の文字で最も右に出現しているものを右端まで持っていくか、その左右逆をする。両方できる場合はその移動距離の短い方を選べばよい。これを繰り返せば答えが求まる (未証明)。

愚直にやると$O(N^2)$である。
およそ$\frac{N}{2}$回の位置検索と削除が発生するため。
まず削除を論理削除にする。つまり`\0`などを代入し、検索の際は読み飛ばすことにする。
検索はしゃくとり法のようにして加速する。文字$c$を左から右へ検索して前回は位置$i$に見付かっていたとき、次は位置$i$から検索を始めればよい。
これで検索にかかる計算量は全体で$O(LN)$になる。
ただしこのためにswapの回数をindexの差だけからは求められなくなってしまうので、これを補う必要がある。
これはsegment木で$0,1$列とその区間中の総和を管理すれば簡単に処理できる。
ただし丁寧に数値を管理すれば追加の計算量なしでも可能だろう。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
using ll = long long;
using namespace std;

template <class Monoid>
struct segment_tree {
    typedef typename Monoid::underlying_type underlying_type;
    int n;
    vector<underlying_type> a;
    const Monoid mon;
    segment_tree() = default;
    segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid()) : mon(a_mon) {
        n = 1; while (n < a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
    }
    void point_set(int i, underlying_type z) { // 0-based
        a[i + n - 1] = z;
        for (i = (i + n) / 2; i > 0; i /= 2) { // 1-based
            a[i - 1] = mon.append(a[2 * i - 1], a[2 * i]);
        }
    }
    underlying_type range_concat(int l, int r) { // 0-based, [l, r)
        underlying_type lacc = mon.unit(), racc = mon.unit();
        for (l += n, r += n; l < r; l /= 2, r /= 2) { // 1-based loop, 2x faster than recursion
            if (l % 2 == 1) lacc = mon.append(lacc, a[(l ++) - 1]);
            if (r % 2 == 1) racc = mon.append(a[(-- r) - 1], racc);
        }
        return mon.append(lacc, racc);
    }
};
struct plus_monoid {
    typedef int underlying_type;
    int unit() const { return 0; }
    int append(int a, int b) const { return a + b; }
};

int main() {
    // input
    string s; cin >> s;
    // solve
    segment_tree<plus_monoid> segtree(s.length(), 1);
    auto use = [&](int i) {
        char c = s[i];
        s[i] = '\0';
        segtree.point_set(i, 0);
        return c;
    };
    int l = 0;
    int r = s.length();
    array<int, 26> next;
    array<int, 26> prev;
    REP (c, 26) {
        next[c] = s.find( c + 'a');
        prev[c] = s.rfind(c + 'a');
    }
    ll result = 0;
    while (r - l >= 2) {
        if (not s[l]) {
            ++ l;
        } else if (not s[r - 1]) {
            -- r;
        } else if (s[l] == s[r - 1]) {
            next[s[r - 1] - 'a'] = s.find( s[r - 1], l + 1);
            prev[s[l]     - 'a'] = s.rfind(s[l],     r - 1);
            use(l);
            use(r - 1);
        } else {
            int & i = next[s[r - 1] - 'a']; if (i != -1 and i <  l) i = s.find( s[r - 1], l);     if (i < l or r - 1 <= i) i = -1;
            int & j = prev[s[l]     - 'a']; if (j != -1 and r <= j) j = s.rfind(s[l],     r - 1); if (j < l + 1 or r <= j) j = -1;
            int i_cost = i == -1 ? INT_MAX : segtree.range_concat(l, i);
            int j_cost = j == -1 ? INT_MAX : segtree.range_concat(j + 1, r);
            char c;
            if (i == -1 and j == -1) {
                result = -1;
                break;  // failure
            } else if (j == -1 or (i != -1 and i_cost < j_cost)) {
                result += i_cost;
                c = use(i);
                use(r - 1);
            } else {
                result += j_cost;
                use(l);
                c = use(j);
            }
            next[c - 'a'] = s.find( c, next[c - 'a']);
            prev[c - 'a'] = s.rfind(c, prev[c - 'a']);
        }
    }
    // output
    printf("%lld\n", result);
    return 0;
}
```
