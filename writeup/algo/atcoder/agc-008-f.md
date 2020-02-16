---
layout: post
redirect_from:
  - /blog/2018/04/12/agc-008-f/
date: "2018-04-12T06:33:45+09:00"
tags: [ "competitive", "writeup", "atcoder", "arc", "tree-dp", "rerooting" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc008/tasks/agc008_f" ]
---

# AtCoder Grand Contest 008: F - Black Radius

## note

-   畳み込みの先は `struct { node_t self; map<int, node_t> sub; };` ただし `struct node_t { int height, second_height, has_favorite; };`
    -   もう少し軽い解法がありそう (1436ms / 2sec)
-   全方位木DPを抽象化した感じのライブラリを書いた
    -   速度よりsignatureのきれいさを優先したのに結局汚して提出しなければいけなかった
    -   そもそもDPではないと思うんだけど誰も指摘してない
    -   全方位木DPについてはちょうど前原先生が絵を書いてた

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">全方位木DP（rerooting）をイラストにしました <a href="https://t.co/TFQsk0rkBL">pic.twitter.com/TFQsk0rkBL</a></p>&mdash; ™ (@tmaehara) <a href="https://twitter.com/tmaehara/status/980787099472297985?ref_src=twsrc%5Etfw">2018年4月2日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

<blockquote class="twitter-tweet" data-lang="ja"><p lang="ja" dir="ltr">セグ木いらんな　左右から伸ばすだけでいいわ</p>&mdash; ™ (@tmaehara) <a href="https://twitter.com/tmaehara/status/981120326137335808?ref_src=twsrc%5Etfw">2018年4月3日</a></blockquote>
<script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>


## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < int(n); ++ (i))
#define ALL(x) begin(x), end(x)
using ll = long long;
using namespace std;
template <class T> inline void chmax2(T & a1, T & a2, T const & b) { if (a1 < b) { a2 = a1; a1 = b; } else if (a2 < b) { a2 = b; } }

/**
 * @brief fold a rooted tree (木DP)
 * @note O(N op) time
 * @note O(N) space, not recursive
 * @note
 *     struct tree_operation {
 *         typedef int type;
 *         type operator () (int i, vector<pair<int, type> > const & args);
 *     };
 */
template <typename TreeOperation>
vector<typename TreeOperation::type> fold_rooted_tree(vector<vector<int> > const & g, int root, TreeOperation op = TreeOperation()) {
    int n = g.size();
    vector<typename TreeOperation::type> data(n);
    stack<tuple<bool, int, int> > stk;
    stk.emplace(false, root, -1);
    while (not stk.empty()) {
        bool state; int x, parent; tie(state, x, parent) = stk.top(); stk.pop();
        if (not state) {
            stk.emplace(true, x, parent);
            for (int y : g[x]) if (y != parent) {
                stk.emplace(false, y, x);
            }
        } else {
            vector<pair<int, typename TreeOperation::type const &> > args;
            for (int y : g[x]) if (y != parent) {
                args.emplace_back(y, data[y]);
            }
            data[x] = op(x, args);
        }
    };
    return data;
}

/**
 * @brief rerooting (全方位木DP)
 * @note O(N op) time
 * @note O(N) space, not recursive
 * @note
 *     struct tree_operation {
 *         typedef int type;
 *         type      add(int i, type data_i, int j, type data_j);  // add    a subtree j to   the root i
 *         type subtract(int i, type data_i, int j, type data_j);  // remove a subtree j from the root i
 *     };
 * @note if add & subtract are slow, you can merge them
 */
template <typename TreeOperation>
vector<typename TreeOperation::type> reroot_folded_rooted_tree(vector<typename TreeOperation::type> data, vector<vector<int> > const & g, int root, TreeOperation op = TreeOperation()) {
    stack<pair<int, int> > stk;
    stk.emplace(root, -1);
    while (not stk.empty()) {
        int x, parent; tie(x, parent) = stk.top(); stk.pop();
        if (parent != -1) {
            typename TreeOperation::type data_parent = {};
            data_parent.self = data[parent].self;  // modified
            op.subtract(parent, data_parent, x, data[x]);
            op.add(x, data[x], parent, data_parent);
        }
        for (int y : g[x]) if (y != parent) {
            stk.emplace(y, x);
        }
    }
    return data;
}

struct node_t {
    int height;
    int second_height;
    int has_favorite;
};
struct tree_operation {
    typedef struct {
        node_t self;
        map<int, node_t> sub;
    } type;
    vector<bool> s;
    tree_operation(vector<bool> const & s) : s(s) {}
    type operator () (int i, vector<pair<int, type const &> > const & args) {
        type data = {};
        data.self.height = 1;
        data.self.has_favorite = s[i];
        for (auto const & arg : args) {
            add(i, data, arg.first, arg.second);
        }
        return data;
    }
    void add(int i, type & data_i, int j, type const & data_j) {  // add a subtree j to the root i
        chmax2(data_i.self.height, data_i.self.second_height, 1 + data_j.self.height);
        data_i.self.has_favorite += data_j.self.has_favorite;
        data_i.sub[j] = data_j.self;
    }
    void subtract(int i, type & data_i, int j, type const & data_j) {  // remove a subtree j from the root i
        if (data_i.self.height == 1 + data_j.self.height) data_i.self.height = data_i.self.second_height;
        data_i.self.has_favorite -= data_j.self.has_favorite;
    }
};
ll solve(int n, vector<vector<int> > const & g, vector<bool> const & s) {
    constexpr int root = 0;
    auto data = reroot_folded_rooted_tree(fold_rooted_tree(g, 0, tree_operation(s)), g, root, tree_operation(s));
    ll cnt = 0;
    REP (i, n) {
        int degree = g[i].size();
        if (degree == 1) {
            cnt += s[i];
        } else {
            vector<int> order = g[i];
            sort(ALL(order), [&](int j1, int j2) { return data[i].sub[j1].height < data[i].sub[j2].height; });
            int r = data[i].sub[order[degree - 2]].height + 1;
            int l = r;
            if (s[i]) {
                l = 0;
            } else {
                for (int j : order) {
                    if (data[i].sub[j].has_favorite) {
                        l = data[i].sub[j].height;
                        break;
                    }
                }
            }
            cnt += max(0, r - l);
        }
    }
    REP (i, n) {
        for (int j : g[i]) if (i < j) {
            int i_height = data[j].sub[i].height;
            int j_height = data[i].sub[j].height;
            if (i_height < j_height) {
                cnt += bool(data[j].sub[i].has_favorite);
            } else if (i_height > j_height) {
                cnt += bool(data[i].sub[j].has_favorite);
            } else {
                cnt += bool(data[i].sub[j].has_favorite or data[j].sub[i].has_favorite);
            }
        }
    }
    return cnt;
}

int main() {
    int n; cin >> n;
    vector<vector<int> > g(n);
    REP (i, n - 1) {
        int a, b; cin >> a >> b;
        -- a; -- b;
        g[a].push_back(b);
        g[b].push_back(a);
    }
    vector<bool> s(n);
    REP (i, n) {
        char c; cin >> c;
        s[i] = c - '0';
    }
    ll answer = solve(n, g, s);
    cout << answer << endl;
    return 0;
}
```
