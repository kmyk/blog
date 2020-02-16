---
layout: post
date: 2018-10-12T17:22:17+09:00
tags: [ "competitive", "writeup", "atcoder", "arc", "grundy", "game", "binary-tree", "trie" ]
"target_url": [ "https://beta.atcoder.jp/contests/arc087/tasks/arc087_c" ]
redirect_from:
  - /writeup/algo/atcoder/arc-087-e/
---

# AtCoder Regular Contest 087: E - Prefix-free Game

## 解法

### 概要

二分木にして様子をよく眺めると$N = 0$で解ければ十分と分かる。
$N = 0$のときのgrundy数は実験をする。
$O(\sum |s_i|)$。

### 詳細

-   editorialの図が分かりやすいのでそれを見て。
-   $N = 0$のときのgrundy数は、$L \le 10^{18}$なので行列累乗か周期性しかないが、式を立てれば前者ではなさげなので後者と分かる。

## メモ

半順序上のantichainみたいな整理のしかたもできる

## 実装

``` c++
#include <bits/stdc++.h>
#define REP(i, n) for (int i = 0; (i) < (int)(n); ++ (i))
using ll = long long;
using namespace std;

template <typename T>
struct trie_t {
    T data;
    array<shared_ptr<trie_t>, 2> children;
};
template <typename T>
shared_ptr<trie_t<T> > trie_insert(shared_ptr<trie_t<T> > original_t, string const & s, T data) {
    if (not original_t) original_t = make_shared<trie_t<T> >();
    auto t = original_t;
    for (char c : s) {
        assert (c == '0' or c == '1');
        int i = c - '0';
        if (not t->children[i]) t->children[i] = make_shared<trie_t<T> >();
        t = t->children[i];
    }
    t->data = data;
    return original_t;
}

int grundy(ll l) {
    return (not l ? 0 : __builtin_ctzll(l) + 1);
}

int go(ll l, shared_ptr<trie_t<bool> > const & a) {
    if (not a) {
        return grundy(l);
    } else if (a->data) {
        return 0;
    } else {
        return go(l - 1, a->children[0]) ^ go(l - 1, a->children[1]);
    }
}

bool solve(int n, ll l, vector<string> const & s) {
    shared_ptr<trie_t<bool> > root = nullptr;
    for (auto const & s_i : s) {
        root = trie_insert(root, s_i, true);
    }
    return go(l + 1, root);
}

int main() {
    int n; ll l; cin >> n >> l;
    vector<string> s(n);
    REP (i, n) cin >> s[i];
    cout << (solve(n, l, s) ? "Alice" : "Bob") << endl;
    return 0;
}
```
