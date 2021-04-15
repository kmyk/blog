---
layout: post
redirect_from:
  - /writeup/algo/codeforces/713-c/
  - /blog/2016/09/14/cf-713-c/
date: "2016-09-14T12:42:37+09:00"
tags: [ "competitive", "writeup", "codeforces", "cf", "weighted-union-heuristic" ]
"target_url": [ "http://codeforces.com/contest/713/problem/C" ]
---

# Codeforces Round #371 (Div. 1) C. Sonya and Problem Wihtout a Legend

解けず。

## solution

$a_i - i$とマージテク。$O(N \log N)$.

$b_i = a_i - i$と取りなおすと、(狭義単調ではなくて)広義単調な数列を作ればよくなる。
$b_i$を操作してできる列$c_i$が広義単調でないとき、その反証となる要素$c_l = \dots = c\_{i-1} = c_i \gt c\_{i+1} = c\_{i+2} = \dots = c_r$がある。
その部分について解消することを考えると、$c' = c'\_l = c'\_{l+1} = \dots = c'\_r$となるようにするのがよい。
このとき$c'$の値であるが、中央値$c' = b\_{\frac{l+r}{2}}$を取るのがよい。これは一度 最小値$b_i$に全てを揃え、これを増やして得をする間$1$ずつ増やしていくことを考えれば示せる。

## similar problems

-   [東京大学プログラミングコンテスト2012 L - じょうしょうツリー](https://beta.atcoder.jp/contests/utpc2012/tasks/utpc2012_12)
    -   editorial: <http://www.utpc.jp/2012/slides/josho.pdf>

## implementation

``` c++
#include <iostream>
#include <vector>
#include <queue>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct half_t {
    int size;
    priority_queue<int> elements;
};
half_t merge(half_t & a, half_t & b) { // merge-tech, destructive
    assert (not a.elements.empty());
    assert (not b.elements.empty());
    if (a.size > b.size) {
        swap(a.size, b.size);
        a.elements.swap(b.elements);
    }
    b.size += a.size;
    while (not a.elements.empty()) {
        b.elements.push(a.elements.top());
        a.elements.pop();
    }
    while (b.elements.size() > (b.size+1)/2) {
        b.elements.pop();
    }
    assert (not b.elements.empty());
    return b;
}
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<half_t> bs(n);
    repeat (i,n) {
        bs[i].size = 1;
        bs[i].elements.push(a[i] - i);
    }
    while (true) {
        bool modified = false;
        vector<half_t> cs;
        for (auto & b : bs) {
            cs.push_back(b);
            while (true) {
                int l = cs.size();
                if (l <= 1) break;
                if (cs[l-2].elements.top() <= cs[l-1].elements.top()) break;
                cs[l-2] = merge(cs[l-2], cs[l-1]);
                cs.pop_back();
                modified = true;
            }
        }
        bs.swap(cs);
        if (not modified) break;
    }
    ll ans = 0; {
        int i = 0;
        for (auto & b : bs) {
            repeat (j, b.size) {
                ans += abs(b.elements.top() - (a[i] - i));
                ++ i;
            }
        }
    }
    cout << ans << endl;
    return 0;
}
```
