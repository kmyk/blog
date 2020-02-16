---
layout: post
date: 2018-08-02T09:56:12+09:00
tags: [ "competitive", "writeup", "atcoder", "tkppc", "convex-hull-trick" ]
"target_url": [ "https://beta.atcoder.jp/contests/tkppc3/tasks/tkppc3_g" ]
---

# 技術室奥プログラミングコンテスト #3: G - パソコンの買い替え

## solution

対数を取ると入力は直線なのでconvex hull trick。$O(N)$。

## note

式を見たら対数を取りたくなるはずだし取った結果を見るとCHTしたくなるはず。
「そのとき最も性能の高いパソコン」が複数あるとき実装がすこし手間だがまあやればできます。
私は諸々でたくさんバグらせました。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;

constexpr double eps = 1e-12;

struct convex_hull_trick_with_monotonicity {
    convex_hull_trick_with_monotonicity() {
        last_x = - INFINITY;
    }
    void add_line(double a, double b, int label) {
        assert (lines.empty() or get<0>(lines.back()) > a - eps);  // weakly monotonically decreasing
        while (lines.size() >= 2 and not is_required(*(lines.end() - 2), lines.back(), make_tuple( a, b, label ))) {
            lines.pop_back();
        }
        lines.emplace_back(a, b, label);
    }
    vector<int> get_min_labels(double x) {
        assert (last_x < x + eps); last_x = x;  // weakly monotonically increasing
        while (lines.size() >= 2 and get_value(0, x) > get_value(1, x) + eps) {
            lines.pop_front();
        }
        double value = get_value(0, x);
        vector<int> labels;
        REP (i, lines.size()) {
            if (get_value(i, x) > value + eps) break;
            labels.push_back(get<2>(lines[i]));
        }
        return labels;
    }
private:
    typedef tuple<double, double, int> line_t;
    bool is_required(line_t f1, line_t f2, line_t f3) {
        double f1a, f1b; tie(f1a, f1b, ignore) = f1;
        double f2a, f2b; tie(f2a, f2b, ignore) = f2;
        double f3a, f3b; tie(f3a, f3b, ignore) = f3;
        return (f2a - f1a) * (f3b - f2b) < (f2b - f1b) * (f3a - f2a) + eps;
    }
    double get_value(int i, double x) {
        double a, b; tie(a, b, ignore) = lines[i];
        return a * x + b;
    }
    deque<line_t> lines;
    double last_x;  // for the assertion
};

int main() {
    // read curves as lines
    int n; cin >> n;
    vector<double> a(n), b(n);  // in log space
    REP (i, n) {
        int a0, b0, r0; cin >> a0 >> b0 >> r0;
        while (r0 and a0 % b0 == 0) {
            -- r0;
            a0 /= b0;  // to normalize
        }
        a[i] = log(b0);
        b[i] = log(a0) - r0 * log(b0);
    }

    // do CHT
    convex_hull_trick_with_monotonicity cht;
    deque<int> order(n);
    iota(ALL(order), 0);
    sort(ALL(order), [&](int i, int j) { return make_pair(a[i], b[i]) < make_pair(a[j], b[j]); });
    map<pair<double, double>, int> index;
    vector<int> count(n);
    for (int i : order) {
        auto key = make_pair(a[i], b[i]);
        if (not index.count(key)) {
            index[key] = i;
            cht.add_line(- a[i], - b[i], i);  // negate
        }
        ++ count[index[key]];
    }

    // serve queries
    vector<int> used(n);
    int k; cin >> k;
    while (k --) {
        int y; cin >> y;
        vector<int> argmax = cht.get_min_labels(y);
        sort(ALL(argmax), [&](int i, int j) { return a[i] < a[j]; });
        for (int i : argmax) {
            if (used[i] < count[i]) {
                ++ used[i];
                break;
            }
        }
    }

    // output
    int answer = accumulate(ALL(used), 0);
    cout << answer << endl;
    return 0;
}
```
