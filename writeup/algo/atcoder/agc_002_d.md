---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_002_d/
  - /writeup/algo/atcoder/agc-002-d/
  - /blog/2016/08/31/agc-002-d/
date: "2016-08-31T03:38:06+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "union-find-tree", "persistence", "persistent-array", "persistent-union-find-tree" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc002/tasks/agc002_d" ]
---

# AtCoder Grand Contest 002 D - Stamp Rally

-   2016年  9月 27日 火曜日 16:53:00 JST
    -   魔法`#pragma GCC optimize ("-O3")`を使ったら通った: <https://beta.atcoder.jp/contests/agc002/submissions/901367>

---

# AtCoder Grand Contest 002 D - Stamp Rally

永続union-findをしたかった。解けず。本番で、ではなくて、未だにTLEから脱せてないので解けてない。しかし定数倍高速化するのに飽きたので終わったことにする。公開されてるテストケースを手元で試した感じだと間に合ってるのだが、gcc/clangのversionの差とかでだめなのだろう。

## 永続union-find木

永続union-find木は、いくらか構成方法はあるだろうが、永続配列があればほぼそのまま実装することができる。

(完全)永続配列は木で比較的容易に実装できる。
根付き木を作り、要素を葉に載せ、要素を変更したらその葉を含む部分木を全て作り直すだけである。
どんな形でも永続には変わりないが探索木であるので平衡させるべきである。
添字の計算が怪しげであるが、segment木などとやっていることはほとんど変わらない。
使用に関して、copyがほとんど定数で使えるが、特に代入の速度は遅いので(`map<int,T>`を考えればよい?)注意すべきだろう。

## implementation

**TLEするので注意。**

特に定数倍高速化してない綺麗なやつ。
した(けどまだ遅い)やつは: <https://beta.atcoder.jp/contests/agc002/submissions/860363>。
参考にしたpekempeyさんのは間に合ってるようなので、上手くやれば間に合うのだろう: <http://pekempey.hatenablog.com/archive/category/%E6%B0%B8%E7%B6%9A%20Union-Find>。

-   `shared_ptr`を使ってしまうとこの問題ではすごくTLEが厳しくなる。memory leakは気にしないようにするしかない。
-   普通はunion-find木の根を求める操作でメモ化をするが、今回それをすると永続配列の複製コストにより損をする。
-   部分永続なやつで我慢しておけば間に合うかもしれない。

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#include <functional>
#include <memory>
#include <cmath>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

// http://web.mit.edu/andersk/Public/6.851-presentation.pdf
template <class T>
struct persistent_array { // fully persistent
    static const int SHIFT_SIZE = 3; // log of the branching factor b
    int size = 0; // the size n
    int shift = -1;
    array<shared_ptr<persistent_array>, (1 << SHIFT_SIZE)> children; // smart pointers are slow...
    // persistent_array *children[1 << SHIFT_SIZE] = {};
    T leaf = {};
    persistent_array(persistent_array const &) = default; // O(b)
    persistent_array() = default;
    persistent_array(int a_size) { // O(n \log_b n + m b \log_b n) for number of update m
        size = a_size;
        if (size == 0) return;
        for (shift = 0; (1 << (shift * SHIFT_SIZE)) < size; ++ shift);
        shift = shift ? (shift - 1) * SHIFT_SIZE : -1;
    }
    T const & get(int i) const { // O(log_b n)
        if (shift == -1) return leaf;
        return children[index_high(i)]->get(index_low(i));
    }
    T & set(int i) { // O(b log_b n), increment m
        if (shift == -1) return leaf;
        auto & p = children[index_high(i)];
        p = p ? make_shared<persistent_array>(*p) : make_shared<persistent_array>(child_size());
        // p = p ? new persistent_array(*p) : new persistent_array(child_size());
        return p->set(index_low(i));
    }
    inline int index_high(int index) const { return index >> shift; }
    inline int index_low (int index) const { return index & ((1 << shift) - 1); }
    inline int child_size()          const { return 1 << shift; }
};

struct persistent_disjoint_sets {
    persistent_array<int> xs;
    persistent_disjoint_sets() = default;
    explicit persistent_disjoint_sets(size_t n) : xs(n) { repeat (i,n) xs.set(i) = -1; }
    bool is_root(int i) { return xs.get(i) < 0; }
    int find_root(int i) { return is_root(i) ? i : find_root(xs.get(i)); } // don't memoize
    int set_size(int i) { return - xs.get(find_root(i)); }
    int union_sets(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (set_size(i) < set_size(j)) swap(i,j);
            xs.set(i) += xs.get(j);
            xs.set(j) = i;
        }
        return i;
    }
};

int main() {
    // input
    int n, m; cin >> n >> m;
    vector<int> a(m), b(m); repeat (e,m) { cin >> a[e] >> b[e]; -- a[e]; -- b[e]; }
    int q; cin >> q;
    vector<int> x(q), y(q), z(q); repeat (i,q) { cin >> x[i] >> y[i] >> z[i]; -- x[i]; -- y[i]; }
    // prepare
    vector<persistent_disjoint_sets> t(m+1);
    t[0] = persistent_disjoint_sets(n);
    repeat (i,m) {
        t[i+1] = t[i];
        t[i+1].union_sets(a[i], b[i]);
    }
    auto query = [&](int i, int x, int y) {
        auto it = t[i];
        x = it.find_root(x);
        y = it.find_root(y);
        return x == y ? it.set_size(x) : it.set_size(x) + it.set_size(y);
    };
    // output
    repeat (i,q) {
        int low = -1, high = m;
        while (low + 1 < high) {
            int mid = (low + high) / 2;
            (query(mid, x[i], y[i]) < z[i] ? low : high) = mid;
        }
        cout << high << endl;
    }
    return 0;
}
```
