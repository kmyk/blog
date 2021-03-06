---
redirect_from:
  - /writeup/algo/codeforces/1074-d/
layout: post
date: 2018-11-05T21:28:44+09:00
tags: [ "competitive", "writeup", "codeforces", "graph", "queries", "online", "union-find-tree", "xor" ]
"target_url": [ "http://codeforces.com/contest/1074/problem/D" ]
---

# Lyft Level 5 Challenge 2018 - Final Round (Open Div. 1): D. Deduction Queries

## 問題概要

長さ $$2^{30}$$ で値が不明な配列 $$a$$ が与えられる。
以下のクエリがオンラインに与えられるので処理せよ:

-   $$a_l \oplus a _ {l+1} \oplus \dots \oplus a_r = x$$ であることが伝えられる
    -   ただし過去の情報と矛盾しているなら無視する
-   過去の情報から $$a_l \oplus a _ {l+1} \oplus \dots \oplus a_r$$ の値が定まるかどうか判定し、定まるならそれを答える

## 解法

### 概要

union-find木を使う。
適切に書けば $$O(n \alpha(n))$$。

### 詳細

$$A[l, r) = a_l \oplus a _ {l+1} \oplus \dots \oplus a _ {r - 1}$$ と書こう。
排他的論理和の性質より $$A[l, r) \oplus A[l, m) = A[m, r)$$ などとして、端点を共有しているならば分割/併合ができる。
しかしこれをそのまま単純にやると $$O(q^2)$$ になる。
$$A[l, l + 1), A[l + 1, l + 2), \dots, A[r - 1, r)$$ の値が伝えられた後に $$A[l, r) = A[l, l + 1) \oplus A[l + 1, l + 2) \oplus \dots \oplus A[r - 1, r)$$ を問われる場合など。
ここで再び排他的論理和であることに注目し、適切な $$m$$ を選んで例えば $$A[m, l), A[m, l + 1), A[m, l + 2), \dots, A[m, r)$$ の値を記憶するようにしておくと、$$A[l, r) = A[m, l) \oplus A[m, r)$$ として高速に求まる。
さてこの $$m$$ の位置をどう決定し管理してやるかであるが、つまりunion-find木と同様な形で処理してやればよい。

## 実装

``` c++
#include <bits/stdc++.h>
using namespace std;

class solver {
    map<int, int> parent;  // a union-find tree
    map<int, uint32_t> value;

    pair<int, uint32_t> get(int l) {
        if (parent.count(l)) {
            int m = parent[l];
            uint32_t a = value[l];
            int r; uint32_t b; tie(r, b) = get(m);
            parent[l] = r;
            value[l] = a ^ b;
            return make_pair(r, a ^ b);
        } else {
            return make_pair(l, 0);
        }
    }

public:
    void update(int l, int r, int x) {
        int r1; uint32_t a; tie(r1, a) = get(l);
        int l1; uint32_t b; tie(l1, b) = get(r);
        if (l1 == r1) return;
        parent[l1] = r1;
        value[l1] = a ^ b ^ x;
    }

    int ask(int l, int r) {
        int r1; uint32_t a; tie(r1, a) = get(l);
        int l1; uint32_t b; tie(l1, b) = get(r);
        if (l1 != r1) return -1;
        return a ^ b;
    }
};

int main() {
    int q; cin >> q;
    solver s;
    int last = 0;
    while (q --) {
        int type, l, r; cin >> type >> l >> r;
        l ^= last;
        r ^= last;
        if (l > r) swap(l, r);
        ++ r;
        if (type == 1) {
            int x; cin >> x;
            x ^= last;
// cerr << "update " << l << " " << r << " " << x << endl;
            s.update(l, r, x);
        } else if (type == 2) {
            last = s.ask(l, r);
// cerr << "ask " << l << " " << r << " -> " << last << endl;
            cout << last << endl;
            if (last == -1) last = 1;
        } else {
            assert (false);
        }
    }
    return 0;
}
```

### 供養: そこそこ頑張ってまじめに区間処理をした版

ここからさらに定数倍の誤魔化しをしたところ、あと3倍速ぐらいで通るのではというところまで迫ってくれた。

``` c++
class solver {
    map<pair<int, int>, int> value;
    map<int, int> l2r, r2l;

    void insert(int l, int r, int x) {
        assert (not value.count(make_pair(l, r)));
        assert (not l2r.count(l));
        assert (not r2l.count(r));
        value[make_pair(l, r)] = x;
        l2r[l] = r;
        r2l[r] = l;
    }
    void erase(int l, int r) {
        assert (value.count(make_pair(l, r)));
        assert (l2r[l] == r);
        assert (r2l[r] == l);
        value.erase(make_pair(l, r));
        l2r.erase(l);
        r2l.erase(r);
    }

public:
    void update(int l, int r, int x) {
        if (ask(l, r) != -1) return;
        if (l2r.count(l)) {
            int r1 = l2r[l];
            if (r1 < r) {
                update(r1, r, x ^ value[make_pair(l, r1)]);
            } else {
                int x1 = value[make_pair(l, r1)];
                erase(l, r1);
                update(l, r, x);
                update(r, r1, x1 ^ x);
            }
        } else if (r2l.count(r)) {
            int l1 = r2l[r];
            if (l < l1) {
                update(l, l1, x ^ value[make_pair(l1, r)]);
            } else {
                int x1 = value[make_pair(l1, r)];
                erase(l1, r);
                update(l1, l, x1 ^ x);
                update(l, r, x);
            }
        } else {
            insert(l, r, x);
        }
    }

    int ask(int l, int r) {
        int acc = 0;
        for (int l1 = l; l1 < r; ) {
            if (not l2r.count(l1)) return -1;
            int r1 = l2r[l1];
            if (r < r1) return -1;
            acc ^= value[make_pair(l1, r1)];
            l1 = r1;
        }
        return acc;
    }
};
```
