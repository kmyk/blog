---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2016-final-g/
  - /blog/2016/12/24/code-festival-2016-final-g/
date: "2016-12-24T21:52:05+09:00"
tags: [ "competitive", "writeup", "atcoder", "codefestival", "minimum-spanning-tree", "kruskals-algorithm" ]
"target_url": [ "https://beta.atcoder.jp/contests/cf16-final-open/tasks/codefestival_2016_final_g" ]
---

# CODE FESTIVAL 2016 Final: G - Zigzag MST

## solution

Kruskal法。クエリを変形して無駄なく打ち切る。$O((N + Q) \log Q)$。

重みで昇順に並べられた無限本の辺で最小全域木なので、直ちにKruskal法が思い出される。
しかしこれを単純に行うと、例えば同じ形のクエリが$Q$個与えられたときに最悪で$O(NQ \log Q)$ぐらいかかる。

単純には、頂点$A, B$間にこの向きのクエリで辺を張ったときこれを覚えておいて次に$A, B$間へのクエリが来たとき(次の辺$B, A+1$の追加も含めて)無視するようにするようなことが考えられる。
しかしこれは$\|A - B\| \le N$であるので、ほとんど落とせない。

ここで、クエリの変形をする。
クエリ$(A, B, C)$が張る辺$e_0, e_1, e_2, e_3, \dots = (A, B), (B, A+1), (A+1, B+1), (B+1, A+2), \dots$であるが、$e_i$を見ているときに$e_j$ ($j \lt i$)については張られていると考えてよい。
つまり$e_0, e_1, e_2, e_3, \dots = (A, B), (A, A+1), (A, B+1), (A, A+2), \dots$や$e_0, e_1, e_2, e_3, \dots = (A, B), (A, A+1), (B, B+1), (A+1, A+2), \dots$であると見なしてよい。
$e_0, e_1, e_2, e_3, e_4, \dots = (A, B), (A, A+1), (B, B+1), (A+1, A+2), (B+1, B+2), \dots$という形を採用すると、$e_0$を除いて$\|\mathrm{dst}(e_i) - \mathrm{src}(e_i)\| = 1$となる。
クエリを$(A, B)$のもの、$(A, A+1), (A+1, A+2), (A+2, A+3), \dots$のもの、$(B, B+1), (B+1, B+2), (B+2, B+3), \dots$のものと分解してやれば、これは上で示した方法で間に合うようになる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <queue>
#include <tuple>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
typedef long long ll;
using namespace std;

struct disjoint_sets {
    vector<int> xs;
    disjoint_sets() = default;
    explicit disjoint_sets(size_t n) : xs(n, -1) {}
    bool is_root(int i) { return xs[i] < 0; }
    int find_root(int i) { return is_root(i) ? i : (xs[i] = find_root(xs[i])); }
    int set_size(int i) { return - xs[find_root(i)]; }
    int union_sets(int i, int j) {
        i = find_root(i); j = find_root(j);
        if (i != j) {
            if (set_size(i) < set_size(j)) swap(i,j);
            xs[i] += xs[j];
            xs[j] = i;
        }
        return i;
    }
    bool is_same(int i, int j) { return find_root(i) == find_root(j); }
};

struct query_t {
    int a, b, c;
    bool is_once;
};
bool operator < (query_t const & x, query_t const & y) {
    return make_tuple(- x.c, x.a, x.b) < make_tuple(- y.c, y.a, y.b);
}
int main() {
    int n, queries; cin >> n >> queries;
    priority_queue<query_t> que;
    repeat (i,queries) {
        int a, b, c; cin >> a >> b >> c;
        que.push({ a,  b,      c,    true });
        que.push({ a, (a+1)%n, c+1, false });
        que.push({ b, (b+1)%n, c+2, false });
    }
    ll acc = 0;
    disjoint_sets sets(n);
    vector<bool> used(n);
    while (sets.set_size(0) != n and not que.empty()) {
        query_t q = que.top(); que.pop();
        if (not q.is_once) {
            if (used[q.a]) continue; // without push
            used[q.a] = true;
            que.push({ (q.a+1)%n, (q.b+1)%n, q.c+2 });
        }
        if (not sets.is_same(q.a, q.b)) {
            sets.union_sets(q.a, q.b);
            acc += q.c;
        }
    }
    cout << acc << endl;
    return 0;
}
```
