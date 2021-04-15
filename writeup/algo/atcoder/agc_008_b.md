---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc_008_b/
  - /writeup/algo/atcoder/agc-008-b/
  - /blog/2016/12/25/agc-008-b/
date: "2016-12-25T23:01:22+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "cumulative-sum" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc008/tasks/agc008_b" ]
---

# AtCoder Grand Contest 008: B - Contiguous Repainting

## 反省

`partial_sum`内部でoverflowしてて$30$分溶かしてしまった。
`OutputIterator`側はちゃんと`long long`にしてたが、内部での和は`InputIterator`側の`int`になってたぽい。普通に`for`回すようにすべきかも。

## solution

長さ$K$の区間以外は自由に塗れる。$O(N)$。

区間$[l, r)$を色$C_l$で塗る、
区間$[l+1, r+1)$を色$C\_{l+1}$で塗る、
区間$[l+2, r+2)$を色$C\_{l+2}$で塗る、$\dots$と続けていけば、最後に塗った区間より左側は自由に塗れる。
これを両側から行なうことを考えれば、任意の長さ$K$の区間$[l,r)$について その区間は全て同じ色で その区間の外は各マスごとに自由な色で塗れることになる。
これは累積和で適当にすれば$O(N)$になる。


## implementation

``` c++
#include <iostream>
#include <vector>
#include <numeric>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
typedef long long ll;
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
int main() {
    int n, k; cin >> n >> k;
    vector<ll> a(n); repeat (i,n) cin >> a[i];
    vector<ll> a_acc { 0 }; whole(partial_sum, a, back_inserter(a_acc));
    vector<ll> b(n); repeat (i,n) b[i] = max<int>(0, a[i]);
    vector<ll> b_acc { 0 }; whole(partial_sum, b, back_inserter(b_acc));
    ll ans = 0;
    repeat (l,n-k+1) {
        int r = l+k;
        setmax(ans, (b_acc[l] - b_acc[0])                         + (b_acc[n] - b_acc[r]));
        setmax(ans, (b_acc[l] - b_acc[0]) + (a_acc[r] - a_acc[l]) + (b_acc[n] - b_acc[r]));
    }
    cout << ans << endl;
    return 0;
}
```
