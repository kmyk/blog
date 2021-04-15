---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/270/
  - /blog/2016/11/15/yuki-270/
date: "2016-11-15T22:14:42+09:00"
tags: [ "competitive", "writeup", "yukicoder", "permutation" ]
"target_url": [ "http://yukicoder.me/problems/no/270" ]
---

# Yukicoder No.270 next_permutation (1)

茶会。`std::next_permutation`の実装の中でintrusiveにやればできそうだと思った(想定解だった)が、もっと楽な方法をizさんに聞いてしまった。

## solution

$k \lt 9!$であるので、次の順列を取る操作はほとんどの場合で末尾の$9$文字程度しか変化しない。
順列の末尾だけ切り出して`std::next_permutation`と$L_1$距離を求め、その他の部分は固定しておけばよい。

階乗$n! \approx {(\frac{n}{e})}^n$の逆関数なので$O(k \log_n n)$だろう。
次の順列を取る操作は一般にならし$O(1)$だが、毎回新規に計算を始めると毎回$n$要素舐めてしまい$O(n)$になる。しかし切り詰めておくことでそのあたりを気にせず`std::next_permutation`に任せることができる。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
int main() {
    int n, k; cin >> n >> k;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<int> b(n); repeat (i,n) cin >> b[i];
    ll ans = 0;
    int l = max(0, n - 20); // 20! = 2.4e18
    ll base = 0; repeat (i,l) base += abs(a[i] - b[i]);
    while (k --) {
        ans += base;
        repeat_from (i,l,n) ans += abs(a[i] - b[i]);
        bool is_not_overflow = next_permutation(a.begin() + l, a.end());
        if (not is_not_overflow) {
            prev_permutation(a.begin() + l, a.end());
            next_permutation(a.begin(),     a.end());
            base = 0; repeat (i,l) base += abs(a[i] - b[i]);
        }
    }
    cout << ans << endl;
    return 0;
}
```
