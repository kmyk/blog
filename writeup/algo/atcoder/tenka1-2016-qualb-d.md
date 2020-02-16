---
layout: post
date: 2018-07-07T07:29:13+09:00
tags: [ "competitive", "writeup", "atcoder", "tenka1", "segment-tree", "events" ]
"target_url": [ "https://beta.atcoder.jp/contests/tenka1-2016-qualb/tasks/tenka1_2016_qualB_d" ]
---

# 天下一プログラマーコンテスト2016予選B: D - 天下一数列にクエリを投げます

## 解法

愚直にやると$(A + 1) \times N$の表を上から順に埋めて$O(A(N + B))$。
区間加算と区間最小値なのでsegment木を使いたいが、2次元であるので難しい。
ここで表をどの向きで埋めるか考える(典型)と、左から埋めればよさそうだと分かる。
imos法のように、加算クエリの端点だけ見ればよくなるのが効く。
列をsegment木にのせ、加算クエリ開始/終了と調査クエリをeventとして順に処理(典型)していけばよい。
$O(N + (A + B) \log (A + B))$。

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define REP_R(i, n) for (int i = int(n) - 1; (i) >= 0; -- (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;

template <class Monoid, class OperatorMonoid>
struct lazy_propagation_segment_tree { // on monoids
    static_assert (is_same<typename Monoid::underlying_type, typename OperatorMonoid::target_type>::value, "");
    typedef typename Monoid::underlying_type underlying_type;
    typedef typename OperatorMonoid::underlying_type operator_type;
    const Monoid mon;
    const OperatorMonoid op;
    int n;
    vector<underlying_type> a;
    vector<operator_type> f;
    lazy_propagation_segment_tree() = default;
    lazy_propagation_segment_tree(int a_n, underlying_type initial_value = Monoid().unit(), Monoid const & a_mon = Monoid(), OperatorMonoid const & a_op = OperatorMonoid())
            : mon(a_mon), op(a_op) {
        n = 1; while (n <= a_n) n *= 2;
        a.resize(2 * n - 1, mon.unit());
        fill(a.begin() + (n - 1), a.begin() + ((n - 1) + a_n), initial_value); // set initial values
        REP_R (i, n - 1) a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]); // propagate initial values
        f.resize(max(0, (2 * n - 1) - n), op.identity());
    }
    void range_apply(int l, int r, operator_type z) {
        assert (0 <= l and l <= r and r <= n);
        range_apply(0, 0, n, l, r, z);
    }
    void range_apply(int i, int il, int ir, int l, int r, operator_type z) {
        if (l <= il and ir <= r) { // 0-based
            a[i] = op.apply(z, a[i]);
            if (i < f.size()) f[i] = op.compose(z, f[i]);
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_apply(2 * i + 1, il, (il + ir) / 2, 0, n, f[i]);
            range_apply(2 * i + 2, (il + ir) / 2, ir, 0, n, f[i]);
            f[i] = op.identity();
            range_apply(2 * i + 1, il, (il + ir) / 2, l, r, z);
            range_apply(2 * i + 2, (il + ir) / 2, ir, l, r, z);
            a[i] = mon.append(a[2 * i + 1], a[2 * i + 2]);
        }
    }
    underlying_type range_concat(int l, int r) {
        assert (0 <= l and l <= r and r <= n);
        return range_concat(0, 0, n, l, r);
    }
    underlying_type range_concat(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) { // 0-based
            return a[i];
        } else if (ir <= l or r <= il) {
            return mon.unit();
        } else {
            return op.apply(f[i], mon.append(
                    range_concat(2 * i + 1, il, (il + ir) / 2, l, r),
                    range_concat(2 * i + 2, (il + ir) / 2, ir, l, r)));
        }
    }
};

struct min_monoid {
    typedef ll underlying_type;
    ll unit() const { return LLONG_MAX; }
    ll append(ll a, ll b) const { return min(a, b); }
};
struct plus_with_llong_max_operator_monoid {
    typedef ll underlying_type;
    typedef ll target_type;
    ll identity() const { return 0; }
    ll apply(underlying_type a, target_type b) const { return b == LLONG_MAX ? LLONG_MAX : a + b; }
    ll compose(underlying_type a, underlying_type b) const { return a + b; }
};

int main() {
    // input
    int N; cin >> N;
    vector<int> a(N);
    REP (i, N) {
        cin >> a[i];
    }
    int A; cin >> A;
    vector<int> L(A), R(A), X(A);
    REP (i, A) {
        cin >> L[i] >> R[i] >> X[i];
        -- L[i];
    }
    int B; cin >> B;
    vector<int> S(B), T(B), K(B);
    REP (j, B) {
        cin >> S[j] >> T[j] >> K[j];
        -- S[j];
        -- K[j];
    }

    // solve
    vector<tuple<int, char, int> > events;
    REP (i, A) {
        events.emplace_back(L[i], 0, i);
        events.emplace_back(R[i], 1, i);
    }
    REP (j, B) {
        events.emplace_back(K[j], 2, j);
    }
    sort(ALL(events));
    lazy_propagation_segment_tree<min_monoid, plus_with_llong_max_operator_monoid> dp(A + 1, 0);
    vector<ll> answer(B);
    for (auto event : events) {
        char c; int i; tie(ignore, c, i) = event;
        if (c == 0) {
            dp.range_apply(i + 1, A + 1, + X[i]);
        } else if (c == 1) {
            dp.range_apply(i + 1, A + 1, - X[i]);
        } else if (c == 2) {
            answer[i] = a[K[i]] + dp.range_concat(S[i], T[i] + 1);
        }
    }

    // output
    REP (j, B) {
        cout << answer[j] << endl;
    }
    return 0;
}
```
