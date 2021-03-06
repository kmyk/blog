---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/435/
  - /blog/2016/10/15/yuki-435/
date: "2016-10-15T00:43:31+09:00"
tags: [ "competitive", "writeup", "yukicoder", "dp", "combination" ]
"target_url": [ "http://yukicoder.me/problems/no/435" ]
---

# Yukicoder No.435 占い(Extra)

制御工学でやった極零相殺の発想が役に立った。好き。

ところで明日(明後日)はICPCアジア地区予選本番。
本番中は通せなかったけれどまあ実質解けてたと言っていいし、この勢いで$5$位ぐらいを取りたい。
あるいはうっかり$1$位を取ってしまってworld finalへ行きたい。

## solution

二項係数との内積のようにして$9$で割った余り。$O(TN)$。

桁ごと分けて足し合わせる操作は$9$で割った余りを取る(ただし$0 \equiv 9$であることに注意し代表元は適当に選ぶ)のと同じである。
このことから、一旦全部足し合わせてから$9$で割った余りを取っても問題ないことも分かる。

$9$で割った余りを取ることなく足し合わせることを考える。
数字列中の各数字がどれくらい最終的な和に効いてくるかは、簡単な例で試すことにより、二項係数そのものであると分かる。
特に、二項係数を$9$で割った余りで十分である。

二項係数の計算は、前処理$O(N)$の$O(1)$で行う必要がある。ただし$9$は素数でないので逆数が取れない数($3$と$6$)が邪魔で単純にはできない。
この困難は含まれる素因数$3$の数を数えておいて最後に分子分母で相殺させれば回避できる。

## implementation

MLEはぎりぎりで回避できた。

``` c++
#include <iostream>
#include <algorithm>
#include <vector>
#include <tuple>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) y) { return (f)(begin(y), end(y), ## __VA_ARGS__); })(x)
using namespace std;
template <class T> void setmax(T & a, T const & b) { if (a < b) a = b; }
template <typename T, typename X> auto vectors(T a, X x) { return vector<T>(x, a); }
template <typename T, typename X, typename Y, typename... Zs> auto vectors(T a, X x, Y y, Zs... zs) { auto cont = vectors(a, y, zs...); return vector<decltype(cont)>(x, cont); }
pair<int,int> zero(int k) {
    int z = 0;
    while (k % 3 == 0) { k /= 3; z += 1; }
    return { k, z };
}
int pack(int k, int z) {
    return z * 9 + k;
}
pair<int,int> unpack(int n) {
    return { n % 9, n / 9 };
}
const int inv[9] = { 0, 1, 5, 0, 7, 2, 0, 4, 8 };
int choose(int n, int r) {
    static vector<int> fact(1, pack(1, 0));
    if (fact.size() <= n) {
        int l = fact.size();
        fact.resize( n + 1);
        repeat_from (i,l,n+1) {
            int pk, pz; tie(pk, pz) = unpack(fact[i-1]);
            int k, z; tie(k, z) = zero(i);
            fact[i] = pack(pk * k % 9, pz + z);
        }
    }
    r = min(r, n - r);
    int pk, pz; tie(pk, pz) = unpack(fact[n]);
    int qk, qz; tie(qk, qz) = unpack(fact[r]);
    int rk, rz; tie(rk, rz) = unpack(fact[n-r]);
    int p = pk * inv[qk] * inv[rk] % 9;
    int z = pz - qz - rz;
    assert (z >= 0);
    return z == 0 ? p : z == 1 ? p * 3 % 9 : 0;
}
int main() {
    int t; cin >> t;
    while (t --) {
        int n, x, a, b, m; cin >> n >> x >> a >> b >> m;
        bool zero = true;
        int acc = x % 10;
        if (x % 10 != 0) zero = false;
        repeat_from (i,1,n) {
            x = ((x ^ a) + b) % m;
            acc = (acc + x % 10 * choose(n-1, i)) % 9;
            if (x % 10 != 0) zero = false;
        }
        if (not zero and acc == 0) acc = 9;
        cout << acc << endl;
    }
    return 0;
}
```
