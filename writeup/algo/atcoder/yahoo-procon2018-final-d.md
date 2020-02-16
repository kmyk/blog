---
layout: post
alias: "/blog/2018/03/01/yahoo-procon2018-final-d/"
date: "2018-03-01T18:03:30+09:00"
tags: [ "competitive", "writeup", "atcoder", "yahoo-procon", "lcp", "suffix-array" ]
"target_url": [ "https://beta.atcoder.jp/contests/yahoo-procon2018-final-open/tasks/yahoo_procon2018_final_d" ]
---

# 「みんなのプロコン 2018」決勝: D - LCP(prefix,suffix)

公式解説がなかったので[準急さんの](https://beta.atcoder.jp/contests/yahoo-procon2018-final/submissions/2126707)を読んだ。

## solution

$s[1]$だけ合わせ、上界下界作って入るか判定。通りはしたが未証明。明らかな嘘解法でも通ってしまうらしいので運良く通っただけの嘘な気がする。
計算量は$O(N (\log N)^2)$だがSA-ISとsparse tableを使えば$O(N)$。

$l\_i \ne 0$ならば$s[1] = s[N - i + 1]$であるので、$s[1] = s[i]$な$i$は全て列挙できる。
$s[1] \ne s[i]$な$i$について適当にして、全体を整合させられるか判定すればよい。
ここで$s[1] \ne s[i]$な$i$は全て異なるとすれば$l$のある種の下界、全て一致するとすれば$l$のある種の上界が得られる。
ただし文字列$s$から数列$l$を構成するのは接尾辞配列を典型的な方法で使えばできる。
こうして得られた下界上界の間に$l$が(pointwiseに)含まれているか判定すればよい。
構成できる場合は必ず成功するが、できない場合に失敗しないことの証明は分からず。

### (たぶん)想定解

union-find木をsegment木っぽく分割管理して$O(N \log N \alpha^{-1}(N))$。

$O(N^2 \alpha^{-1}(N))$は明らか。
union-find木を用意し文字の一致を管理する。
各項$l\_i$ごとに次のふたつと見て、前者を先に全て処理し、後者を後に確認すればよい。

-   区間$s[1 : l\_i]$と$s[N - i + 1 : N - i + l\_i]$の一致クエリ
-   文字$s[1 + l\_i]$と$s[N - i + 1 + l\_i]$の不一致クエリ

$l\_i$が長い場合が問題。
しかし範囲と範囲の各点union操作ができるunion-find木があれば解決する。
いい感じに頑張ればできる。

なお問題は存在性の判定だけを要求している。
この方法だと構成までできるので、これが想定でない可能性は残る。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using namespace std;

template <class String>
void suffix_array(String const & s, vector<int> & sa, vector<int> & rank) {
    int n = s.size();
    sa.resize(n + 1);
    rank.resize(n + 1);
    REP (i, n + 1) {
        sa[i] = i;
        rank[i] = i < n ? s[i] : -1;
    }
    auto rankf = [&](int i) { return i <= n ? rank[i] : -1; };
    vector<int> nxt(n + 1);
    for (int k = 1; k <= n; k <<= 1) {
        auto cmp = [&](int i, int j) { return make_pair(rank[i], rankf(i + k)) < make_pair(rank[j], rankf(j + k)); };
        sort(sa.begin(), sa.end(), cmp);
        nxt[sa[0]] = 0;
        REP3 (i, 1, n + 1) {
            nxt[sa[i]] = nxt[sa[i - 1]] + (cmp(sa[i - 1], sa[i]) ? 1 : 0);
        }
        rank.swap(nxt);
    }
}

template <class String>
vector<int> longest_common_prefix_array(String const & s, vector<int> const & sa, vector<int> const & rank) {
    int n = s.size();
    vector<int> lcp(n);
    int h = 0;
    lcp[0] = 0;
    REP (i, n) {
        int j = sa[rank[i] - 1];
        if (h > 0) -- h;
        while (j + h < n and i + h < n and s[j + h] == s[i + h]) ++ h;
        lcp[rank[i] - 1] = h;
    }
    return lcp;
}

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
struct min_monoid {
    typedef int underlying_type;
    int unit() const { return INT_MAX; }
    int append(int a, int b) const { return min(a, b); }
};

vector<int> construct_l(vector<int> const & s) {
    int n = s.size();
    vector<int> sa, rank; suffix_array(s, sa, rank);
    vector<int> lcp = longest_common_prefix_array(s, sa, rank);
    segment_tree<min_monoid> segtree(n);
    REP (i, n) {
        segtree.point_set(i, lcp[i]);
    }
    vector<int> l(n);
    REP (i, n - 1) {
        int a = rank[0];
        int b = rank[n - i - 1];
        if (a > b) swap(a, b);
        l[i] = segtree.range_concat(a, b);
    }
    l[n - 1] = n;
    return l;
}

bool solve(int n, vector<int> const & l) {
    // lower bound
    vector<int> s(n);
    iota(ALL(s), 0);
    REP (i, n) if (l[i] != 0) s[n - i - 1] = 0;
    vector<int> ls = construct_l(s);
    // upper bound
    vector<int> t(n, 1);
    REP (i, n) if (l[i] != 0) t[n - i - 1] = 0;
    vector<int> lt = construct_l(t);
    // check
    REP (i, n) {
        if (not (ls[i] <= l[i] and l[i] <= lt[i])) {
            return false;
        }
    }
    return true;
}

int main() {
    int n; scanf("%d", &n);
    vector<int> l(n); REP (i, n) scanf("%d", &l[i]);
    bool result = solve(n, l);
    printf("%s\n", result ? "Yes" : "No");
    return 0;
}
```
