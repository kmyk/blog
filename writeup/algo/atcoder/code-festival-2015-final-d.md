---
layout: post
redirect_from:
  - /writeup/algo/atcoder/code-festival-2015-final-d/
  - /blog/2015/11/21/code-festival-2015-final-d/
date: 2015-11-21T17:19:01+09:00
tags: [ "competitive", "writeup", "codefestival", "atcoder", "segment-tree", "starry-sky-tree", "range-add-query", "range-maximum-query", "library" ]
---

# CODE FESTIVAL 2015 決勝 D - 足ゲームII

問題読んで即ライブラリを貼った。

<!-- more -->

## [D - 足ゲームII](https://beta.atcoder.jp/contests/code-festival-2015-final-open/tasks/codefestival_2015_final_d) {#d}

### 問題

区間が$N$個与えられる。
この中から$N-1$個選んだときの最も多く重なっている箇所の重なりの数、の最小値を答えよ。

### 解法

区間に対する一様な加算と最大値の取得が可能なデータ構造を作ればよい。
segment treeで可能。

特にこの2つのクエリが可能なsegment treeを、これが必要な問題のひとつの名前を取って、starry sky treeと呼ぶらしい。

### 実装

ライブラリが綺麗でなかったので書き直したもの。
minimumに対応したものが欲しい場合は、コメントが付いてる箇所4つを書き換えればよい。

``` c++
#include <iostream>
#include <vector>
#include <cmath>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
using namespace std;

struct starry_sky_tree {
    int n;
    vector<int> a, b; // add, max
    explicit starry_sky_tree(int a_n) {
        n = pow(2,ceil(log2(a_n)));
        a.resize(2*n-1); // fill 0, unit of add
        b.resize(2*n-1); // fill 0, unit of max
    }
    void range_add(int l, int r, int z) {
        range_add(0, 0, n, l, r, z);
    }
    void range_add(int i, int il, int ir, int l, int r, int z) {
        if (l <= il and ir <= r) {
            a[i] += z;
            b[i] += z;
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_add(2*i+1, il, (il+ir)/2, l, r, z);
            range_add(2*i+2, (il+ir)/2, ir, l, r, z);
            b[i] = a[i] + max(b[2*i+1], b[2*i+2]); // max
        }
    }
    int range_max(int l, int r) {
        return range_max(0, 0, n, l, r);
    }
    int range_max(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return b[i];
        } else if (ir <= l or r <= il) {
            return 0; // unit of max
        } else {
            return a[i] + max( // max
                    range_max(2*i+1, il, (il+ir)/2, l, r),
                    range_max(2*i+2, (il+ir)/2, ir, l, r));
        }
    }
};

#define MAX_T 100000
int main() {
    int n; cin >> n;
    vector<int> s(n), t(n);
    repeat (i,n) cin >> s[i] >> t[i];
    starry_sky_tree q(MAX_T+1);
    repeat (i,n) q.range_add(s[i], t[i], 1);
    int result = 1000000007;
    repeat (i,n) {
        q.range_add(s[i], t[i], -1);
        result = min(result, q.range_max(0, MAX_T+1));
        q.range_add(s[i], t[i], +1);
    }
    cout << result << endl;
    return 0;
}
```
