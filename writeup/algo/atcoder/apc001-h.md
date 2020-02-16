---
layout: post
date: 2018-07-25T09:11:52+09:00
tags: [ "competitive", "writeup", "atcoder", "apc", "tree", "construction" ]
"target_url": [ "https://beta.atcoder.jp/contests/apc001/tasks/apc001_h" ]
---

# AtCoder Petrozavodsk Contest 001: H - Generalized Insertion Sort

## note

解説をちょっと覗いた。
テストケースが弱い可能性がある。実際に私の解法は落とせた。
左端から整列する場合だけ考えて、なぜ問題名がGeneralized Insertion Sortなのか分かってなかったので特殊例かもしれない。
つまり何も理解しないままACだけ点灯させた。
というかinsertion sortだと分かってたら木上でも自明では。

以下の解法は自分の理解のために書かれた正しいものである。
ところで「葉パス」って一般的な名称なのだろうか。

## solution

直線の場合だけなら簡単で、合流があるのが難しい。そこで合流点の奥の葉っぽい部分だけに絞り、なにか重軽分解ぽくやる。
丁寧にやれば$O(N \log N)$ですが、$O(N^3 \log N)$ぐらいの雑さでも大丈夫。

まずもちろん直線の場合を考えよう。
これは右端からのinsertion sortそのものであり、挿入が$1$回のクエリなので高々$N$クエリで可能。

さてこれが木になるとどう難しいのか。
厄介なのは合流があること。
次数$2$以上の点より上の部分はその下の部分同士の干渉によって壊れてしまう。
かといって各葉を$1$枚ずつ構成し削除していくのでは$O(N^2)$クエリかかってしまう。

合流が難しいと言ったが、合流する点の下側、つまり自身かそれより下に次数$2$以上の点を含まない部分(以下、editorialにならって葉パスと呼ぶ)については簡単である。
特に次が言える: 「任意の時点から、$N$回の操作を使って、その時点における葉パスをすべて完成させられる」。
葉パス内部では直線の場合と同様にできるので、$N$回かけてすべての頂点を$1$回以上根に移動させられればよく、この移動は可能なのでで葉パスを作れる。
さらに次も言える: 「その時点における葉パスをすべて消すという処理を$O(\log N)$回すれば、すべての頂点を消せる」。
これは「すべて消すという処理のたびに葉の数が半分以下になる」ことから言える。
あるいは消すのに最低$1$回かかるような最小の木は$1$頂点、最低$2$回は$3$頂点、最低$3$回だと$7$頂点、$\dots$と確認していってもよい。

## implementation

注意: この実装は$p_i = i$かつ$a_i = N - i - 1$で落とせる。

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
#define REP3(i, m, n) for (int i = (m); (i) < (int)(n); ++ (i))
#define ALL(x) begin(x), end(x)
using namespace std;
template <class T> inline void chmax(T & a, T const & b) { a = max(a, b); }

int main() {
    // input
    int n; cin >> n;
    vector<int> parent(n, -1);
    vector<vector<int> > children(n);
    REP3 (x, 1, n) {
        cin >> parent[x];
        children[parent[x]].push_back(x);
    }
    vector<int> a(n);
    REP (x, n) {
        cin >> a[x];
    }

    // solve
    constexpr int root = 0;

    auto get_leaf = [&](int x) {
        while (not children[x].empty()) {
            x = children[x].back();
        }
        return x;
    };

    auto cut_leaves = [&](int x) {
        while (x != root and a[x] == x and children[x].empty()) {
            int y = parent[x];
            auto it = find(ALL(children[y]), x);
            children[y].erase(it);
            x = y;
        }
    };
    REP (x, n) {
        cut_leaves(x);
    }

    vector<bool> is_leafish(n);
    auto update_leafish = [&](int x) {
        while (children[x].empty() or (children[x].size() == 1 and is_leafish[children[x][0]])) {
            is_leafish[x] = true;
            if (x == root) {
                break;
            } else {
                x = parent[x];
            }
        }
    };
    REP (x, n) {
        update_leafish(x);
    }

    vector<int> lookup(n);  // lookup : a_x |-> x
    REP (x, n) {
        lookup[a[x]] = x;
    }

    vector<int> ops;
    auto op = [&](int x) {
        assert (x != -1);
        assert (not (a[x] == x and children[x].empty()));
        ops.push_back(x);
        int last = a[root];
        for (int y = x; y != -1; y = parent[y]) {
            swap(a[y], last);
            lookup[a[y]] = y;
        }
        if (children[x].empty()) {
            cut_leaves(x);
            update_leafish(x);
        }
    };

    auto get_deepest_leafish_value = [&]() {
        vector<bool> is_fixed(n);
        function<void (int)> go1 = [&](int x) {
            if (is_leafish[x]) {
                vector<int> path;
                for (int y = x; ; ) {
                    path.push_back(y);
                    if (children[y].empty()) {
                        break;
                    } else {
                        y = children[y][0];
                    }
                }
                auto it = find(ALL(path), lookup[x]);
                if (it != path.end()) {
                    bool pred = true;
                    for (int i = 0; it + i != path.end(); ++ i) {
                        if (a[*(it + i)] != path[i]) {
                            pred = false;
                            break;
                        }
                    }
                    for (int i = 0; it + i != path.end(); ++ i) {
                        is_fixed[a[*(it + i)]] = true;
                    }
                }
            } else {
                for (int y : children[x]) {
                    go1(y);
                }
            }
        };
        go1(root);

        auto result = make_pair(-1, -1);
        function<void (int, int)> go2 = [&](int x, int depth) {
            if (is_leafish[a[x]] and not is_fixed[a[x]]) {
                chmax(result, make_pair(depth, a[x]));
            }
            for (int y : children[x]) {
                go2(y, depth + 1);
            }
        };
        go2(root, 0);
        return result.second;
    };

    while (not children[root].empty()) {
        int x = a[root];
        if (is_leafish[x]) {
            if (x == root or not is_leafish[parent[x]]) {
                op(get_leaf(x));
            } else {
                op(lookup[parent[x]]);
            }
        } else {
            op(lookup[get_deepest_leafish_value()]);
        }
    }

    // output
    cout << ops.size() << endl;
    for (int op : ops) {
        cout << op << endl;
    }
    assert (is_sorted(ALL(a)));
    assert (ops.size() <= 25000 * n / 2000);
    return 0;
}
```
