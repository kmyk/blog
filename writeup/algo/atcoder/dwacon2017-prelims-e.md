---
layout: post
alias: "/blog/2016/12/21/dwacon2017-prelims-e/"
date: "2016-12-21T15:17:39+09:00"
tags: [ "competitive", "writeup", "atcoder", "dwacon", "dp", "segment-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/dwacon2017-prelims/tasks/dwango2017qual_e" ]
---

# 第3回 ドワンゴからの挑戦状 予選: E - 偶奇飴分け

本番中でもsegment木だろうなというのは想像できたが、部分点DPを書いて通過圏内に入り、体力を使い切って/満足してしまった。

natsugiriさんの[提出](https://beta.atcoder.jp/contests/dwacon2017-prelims/submissions/1029490)が(比較的)読みやすかったのでこれを大いに参考にした。
多次元配列を`- inf`で埋めるのを`memset(val, 0xc0, sizeof val);`と書いていたのは面白かった。

## solution

segment木で区間を管理する。
区間について、その区間の左端付近/右端付近での飴玉の移し方、その区間の手前で非空になっていてほしい皿の数(の偶奇)、その区間中で非空になる皿の数(の偶奇)を固定し、そのような時の得られる飴玉の最大値を管理する。$O(Q \log N)$。

見る区間$[l,r)$として、
左側の隣接区間の右端の皿$l-1$ / 左端の皿$l$ / 右端の皿$r-1$ / 右側の隣接区間の左端の皿$r$の移し方を
それぞれ$l\_l, l\_r, r\_l, r\_r \in 2$とし、
移動後に区間$[l,r)$中の非空な皿の数の偶奇を$p \in 2$、
移動後の区間$[0,l)$中の非空な皿の数の偶奇を$q \in 2$
とする。
これらを固定したときの元々の区間$[l,r)$中の飴玉から得られる数の最大値を$\mathrm{dp}\_{l,r}(l_l, l_r, r_l, r_r, p, q)$とする。
この関数$\mathrm{dp} : \mathbb{N}^2 \times 2^6 \to \mathbb{N} $は区間$[l_1,r_1)$と区間$[l_2,r_2)$について$r_1 = l_2$であれば合成できる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <functional>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
const int inf = 1e9+7;

template <typename T>
struct segment_tree { // on monoid
    int n;
    vector<T> a;
    function<T (T,T)> append; // associative
    T unit; // unit
    segment_tree() = default;
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

const int LEFT  = 0;
const int RIGHT = 1;
struct node_t {
    bool is_unit;
    int dp[2][2][2][2][2][2];
    node_t() {
        is_unit = true;
    }
    node_t(int x) {
        is_unit = false;
        repeat (ll,2) repeat (lr,2) repeat (rl,2) repeat (rr,2) repeat (len,2) repeat (top,2) dp[ll][lr][rl][rr][len][top] = - inf;
        repeat (c,2) repeat (ll,2) repeat (rr,2) {
            int len = (ll == RIGHT) or (rr == LEFT);
            bool pred = (c == RIGHT) and (len == 0);
            repeat (top,2) {
                dp[ll][c][c][rr][len][top] = (top == pred ? x : 0);
            }
        }
    }
    node_t operator * (node_t const & other) const {
        if (this->is_unit) return other;
        if (other.is_unit) return *this;
        auto const & a = this->dp;
        auto const & b = other.dp;
        node_t result;
        result.is_unit = false;
        repeat (ll,2) repeat (lr,2) repeat (rl,2) repeat (rr,2) repeat (len,2) repeat (top,2) result.dp[ll][lr][rl][rr][len][top] = - inf;
        repeat (ll,2) repeat (lr,2) repeat (cl,2) repeat (cr,2) repeat (rl,2) repeat (rr,2) repeat (len_a,2) repeat (len_b,2) repeat (top_a,2) {
            int len   = len_a ^ len_b;
            int top_b = top_a ^ len_a;
            setmax(result.dp[ll][lr][rl][rr][len][top_a], a[ll][lr][cl][cr][len_a][top_a] + b[cl][cr][rl][rr][len_b][top_b]);
        }
        return result;
    }
    int value() const {
        assert (not is_unit);
        int result = 0;
        repeat (lr,2) repeat (rl,2) repeat (len,2) {
            setmax(result, dp[LEFT][lr][rl][RIGHT][len][lr]);
        }
        return result;
    }
};

int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    segment_tree<node_t> segtree(n, node_t(), multiplies<node_t>());
    repeat (k,n) segtree.point_update(k, node_t(a[k]));
    int q; cin >> q;
    while (q --) {
        int k, x; cin >> k >> x; -- k;
        segtree.point_update(k, node_t(x));
        cout << segtree.range_concat(0, n).value() << endl;
    }
    return 0;
}
```

### 部分点

``` c++
#include <iostream>
#include <vector>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
typedef long long ll;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <typename X, typename T> auto vectors(X x, T a) { return vector<T>(x, a); }
template <typename X, typename Y, typename Z, typename... Zs> auto vectors(X x, Y y, Z z, Zs... zs) { auto cont = vectors(y, z, zs...); return vector<decltype(cont)>(x, cont); }
const int inf = 1e9+7;
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    a.push_back(0); ++ n; // 多
    a.push_back(0); ++ n; // め
    a.push_back(0); ++ n; // に
    a.push_back(0); ++ n; // 念のため
    int q; cin >> q;
    assert (q == 1);
    while (q --) {
        int k, x; cin >> k >> x; -- k;
        a[k] = x;
        vector<vector<vector<vector<int> > > > dp = vectors(n+1, 2, 2, 2, - inf);
        dp[0][0][0][0] = 0;
        repeat (i,n) repeat (p,2) repeat (x,2) repeat (y,2) repeat (z,2) {
            int ax = x and i-2 >= 0 ? a[i-2] : 0;
            int az = not z and i < n ? a[i] : 0;
            int np = ax + az ? p^1 : p;
            setmax(dp[i+1][np][y][z], dp[i][p][x][y] + (np % 2 == 1 ? ax + az : 0));
        }
        int ans = 0;
        repeat (p,2) repeat (x,2) repeat (y,2) setmax(ans, dp[n][p][x][y]);
        cout << ans << endl;
    }
    return 0;
}
```
