---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/130/
  - /blog/2016/10/21/yuki-130/
date: "2016-10-21T17:05:09+09:00"
tags: [ "competitive", "writeup", "yukicoder", "tree", "dp", "bits", "trie" ]
"target_url": [ "http://yukicoder.me/problems/no/130" ]
---

# Yukicoder No.130 XOR Minimax

実際に木を作ると実装が楽だからそこを面白がられて星がたくさんなのかな、と思って他人の提出を見たら違った。

## solution

$2$進数展開で二分木でもあるTrie木を作って木DP。$O(N)$。

選ぶ非負整数$x$の$i$番目のbitを$1$にするのは、この二分木の深さ$i$の位置の頂点の左右の子を反転させるということ。
そうしてできた木の(右を$1$左を$0$として)最も右の葉を最も左にし、その位置を出力すればよい。
これは単純な木DPで求まる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <memory>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;
struct tree_t {
    shared_ptr<tree_t> left, right;
};
shared_ptr<tree_t> insert(shared_ptr<tree_t> t, int32_t x, int i) {
    if (not t) t = make_shared<tree_t>();
    if (i == -1) return t;
    shared_ptr<tree_t> & nt = (x & (1 << i) ? t->right : t->left);
    nt = insert(nt, x, i-1);
    return t;
}
int dfs(shared_ptr<tree_t> const & t, int i) {
    return
        not t ? 0 :
        not t->left  ? dfs(t->right, i-1) :
        not t->right ? dfs(t->left,  i-1) :
        min(dfs(t->left, i-1), dfs(t->right, i-1)) + (1 << i);
}
int main() {
    int n; cin >> n;
    vector<int32_t> a(n); repeat (i,n) cin >> a[i];
    shared_ptr<tree_t> root = nullptr;
    repeat (i,n) root = insert(root, a[i], 31);
    cout << dfs(root, 31) << endl;
    return 0;
}
```
