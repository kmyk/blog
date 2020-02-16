---
layout: post
alias: "/blog/2015/10/23/arc-045-b/"
date: 2015-10-23T02:27:34+09:00
tags: [ "atcoder", "arc", "competitive", "writeup", "segment-tree", "range-add-query", "range-minimum-query", "imos", "cumulative-sum" ]
---

# AtCoder Regular Contest 045 B - ドキドキデート大作戦高橋君

segment treeへの苦手意識が薄まったかも。

<!-- more -->

## [B - ドキドキデート大作戦高橋君](https://beta.atcoder.jp/contests/arc045/tasks/arc045_b)

### 問題

教室が一列に並んでいる。
連続した教室の区間が複数与えられ、この区間をそれぞれ掃除する。
それがなくても全ての教室が掃除されるような区間を全て答えよ。

### 解法

各区間について、その区間の中の全ての教室が複数の区間に含まれるかどうかを見る。

imos法を使って、各教室についていくつの区間に含まれるかを計算する。
次に、各教室が複数の区間に含まれるかどうかの$0$ or $1$の列について、累積和を取る。
こうすれば各区間について$O(1)$で判定できる。全体で$O(n + m)$。

素直にsegment treeを書いても通る。

### 実装

#### imos

``` c++
#include <iostream>
#include <vector>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
int main() {
    int n, m; cin >> n >> m;
    vector<int> s(m), t(m); repeat (i,m) cin >> s[i] >> t[i];
    vector<int> imos(n+1);
    repeat (i,m) {
        imos[s[i]-1] += 1;
        imos[t[i]]   -= 1;
    }
    vector<int> acc(n+2);
    int imos_acc = 0;
    repeat (i,n+1) {
        imos_acc += imos[i];
        acc[i+1] += acc[i] + (imos_acc >= 2 ? 1 : 0);
    }
    vector<int> result;
    repeat (i,m) {
        if (acc[t[i]] - acc[s[i]-1] == t[i] - s[i] + 1) {
            result.push_back(i+1);
        }
    }
    cout << result.size() << endl;
    for (int it : result) cout << it << endl;
    return 0;
}
```

#### segment tree

``` c++
#include <iostream>
#include <vector>
#include <cmath>
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define repeat(i,n) repeat_from(i,0,n)
using namespace std;
struct segment_tree {
    int n;
    vector<int> a;
    vector<int> b;
    explicit segment_tree(int a_n) {
        n = a_n;
        a.resize(pow(2,ceil(log2(n))+1)-1);
        b.resize(pow(2,ceil(log2(n))+1)-1);
    }
    void range_add_query(int l, int r, int v) { // [l, r)
        range_add_query(0, 0, n, l, r, v);
    }
    void range_add_query(int i, int il, int ir, int l, int r, int v) {
        if (l <= il and ir <= r) {
            a[i] += v;
            b[i] += v;
        } else if (ir <= l or r <= il) {
            // nop
        } else {
            range_add_query(i*2+1, il, (il + ir) / 2, l, r, v),
            range_add_query(i*2+2, (il + ir) / 2, ir, l, r, v);
            b[i] = a[i] + min(
                range_minimum_query(i*2+1, il, (il + ir) / 2, 0, n),
                range_minimum_query(i*2+2, (il + ir) / 2, ir, 0, n));
        }
    }
    int range_minimum_query(int l, int r) { // [l, r)
        return range_minimum_query(0, 0, n, l, r);
    }
    int range_minimum_query(int i, int il, int ir, int l, int r) {
        if (l <= il and ir <= r) {
            return b[i];
        } else if (ir <= l or r <= il) {
            return 1000000007; // INT_MAX causes overflow
        } else {
            return a[i] + min(
                range_minimum_query(i*2+1, il, (il + ir) / 2, l, r),
                range_minimum_query(i*2+2, (il + ir) / 2, ir, l, r));
        }
    }
};
int main() {
    int n, m; cin >> n >> m;
    vector<int> s(m), t(m); repeat (i,m) cin >> s[i] >> t[i];
    segment_tree tree(n);
    repeat (i,m) tree.range_add_query(s[i]-1, t[i], 1);
    vector<int> result;
    repeat (i,m) if (2 <= tree.range_minimum_query(s[i]-1, t[i])) result.push_back(i+1);
    cout << result.size() << endl;
    for (int it : result) cout << it << endl;
    return 0;
}
```

29, 30行目の`b[i]`を更新するところで、`range_minimum_query`の`l, r`を`0, n`でなく`l, r`にしてバグらせた。
