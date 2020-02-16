---
layout: post
redirect_from:
  - /blog/2016/04/09/arc-050-d/
date: 2016-04-09T01:01:39+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "suffix-array", "longest-common-prefix", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc050/tasks/arc050_d" ]
---

# AtCoder Regular Contest 050 D - Suffix Concat

## 解法

suffix array + longest common prefix array。$O(N (\log N)^2)$。

接尾辞配列そのままがかなり答えに近そうである。
もちろんそれで通るはずがなくて、接尾辞配列の末尾の辺りの処理が問題である。
例としては、入力`bab`で接尾辞`b`と接尾辞`bab`の順、あるいは入力`aba`で接尾辞`a`と接尾辞`aba`の順、である。
これは、接尾辞$S,T$の順を$S \lt T$でなく$S \oplus T \lt T \oplus S$で判定することで解決する。

$S \oplus T \lt T \oplus S$の判定が問題である。
これはまず$S$と$T$のどちらかがどちらかのprefixになっているかどうかで場合分けをしていけばよい。
prefixであることの判定にはlongest common prefixを使う(蟻本に載ってる)。

## 実装

`sort`の第3引数のあたりでclangがこける。gccなら問題ない。なぜ。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <functional>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
vector<int> suffix_array(string const & s) {
    int n = s.length();
    vector<int> sa(n+1);
    vector<int> rank(n+1);
    repeat (i,n+1) {
        sa[i] = i;
        rank[i] = i < n ? s[i] : -1;
    }
    auto rankf = [&](int i) { return i <= n ? rank[i] : -1; };
    vector<int> nxt(n+1);
    for (int k = 1; k <= n; k <<= 1) {
        auto cmp = [&](int i, int j) { return make_pair(rank[i], rankf(i + k)) < make_pair(rank[j], rankf(j + k)); };
        sort(sa.begin(), sa.end(), cmp);
        nxt[sa[0]] = 0;
        repeat_from (i,1,n+1) {
            nxt[sa[i]] = nxt[sa[i-1]] + (cmp(sa[i-1], sa[i]) ? 1 : 0);
        }
        rank.swap(nxt);
    }
    return sa;
}
vector<int> longest_common_prefix_array(string const & s, vector<int> const & sa) {
    int n = s.length();
    vector<int> rank(n+1);
    repeat (i,n+1) rank[sa[i]] = i;
    vector<int> lcp(n);
    int h = 0;
    lcp[0] = 0;
    repeat (i,n) {
        int j = sa[rank[i] - 1];
        if (h > 0) -- h;
        while (j + h < n and i + h < n and s[j + h] == s[i + h]) ++ h;
        lcp[rank[i] - 1] = h;
    }
    return lcp;
}
template <typename T>
struct segment_tree { // on monoid
    int n;
    vector<T> a;
    function<T (T,T)> append; // associative
    T unit;
    template <typename F>
    segment_tree(int a_n, T a_unit, F a_append) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1, a_unit);
        unit = a_unit;
        append = a_append;
    }
    void point_update(int i, T z) {
        a[i+n-1] = z;
        for (i = (i+n)/2; i > 0; i /= 2) {
            a[i-1] = append(a[2*i-1], a[2*i]);
        }
    }
    T range_concat(int l, int r) {
        return range_concat(0, 0, n, l, r);
    }
    T range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return a[i];
        } else if (ir <= l or r <= il) {
            return unit;
        } else {
            return append(
                    range_concat(2*i+1, il, (il+ir)/2, l, r),
                    range_concat(2*i+2, (il+ir)/2, ir, l, r));
        }
    }
};
int main() {
    int n; string s; cin >> n >> s;
    vector<int> sa = suffix_array(s);
    vector<int> rank(n+1);
    repeat (i,n+1) rank[sa[i]] = i;
    vector<int> lcp = longest_common_prefix_array(s, sa);
    segment_tree<int> rmq(n, n+1, [&](int i, int j) { return min(i,j); });
    repeat (i,n) rmq.point_update(i, lcp[i]);
    vector<int> ans(n); repeat (i,n) ans[i] = i;
    function<bool (int, int)> cmp = [&](int i, int j) {
        if (i >= j) return not cmp(j,i);
        int li = n - i;    //   iiii-iiii jjjj
        int lj = n - j;    //   jjjj iiii-iiii
        int ri = rank[i];  //    h    h'   h''
        int rj = rank[j];
        int h = rmq.range_concat(min(ri,rj), max(ri,rj));
        if (h == lj) {
            int rk = rank[i+lj];
            h = rmq.range_concat(min(ri,rk), max(ri,rk));
            if (h == li - lj) {
                return rank[j] < rank[i + li - lj];
            } else {
                return rank[i + lj] < rank[i];
            }
        } else {
            return rank[i] < rank[j];
        }
    };
    sort(ans.begin(), ans.end(), cmp);
    repeat (i,n) cout << ans[i]+1 << endl;
    return 0;
}
```
