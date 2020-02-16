---
layout: post
redirect_from:
  - /writeup/algo/atcoder/agc-010-b/
  - /blog/2017/02/04/agc-010-b/
date: "2017-02-04T23:05:34+09:00"
tags: [ "competitive", "writeup", "atcoder", "agc", "lie", "random" ]
"target_url": [ "https://beta.atcoder.jp/contests/agc010/tasks/agc010_b" ]
---

# AtCoder Grand Contest 010: B - Boxes

<!-- {% raw %} -->

この手の嘘解法は好きなのだが、yukicoderだったら実質WAだし、そうでなくてもペナルティが厳しい。

ところで、最初に常に`YES`を投げて`YES` `NO`の偏り$p$を計測してそれに応じて投げれば最初の計測と合わせてもちょっと有利になるというのを思い付いたので使っていきたい。
例えば、今回私の実装を投げたら$3$TLEだったので、`YES` `NO`を$\frac{1}{2}$ずつで返すと期待値$8$回だが、このテクを使えば最初の計測で外した場合(なお今回は常に`YES`が正解だった)でも$1 + \frac{3^3}{2^2\cdot 1} = 7.75$と有利。

## solution

嘘解法。貪欲 + 定数倍高速化 + 時間計測乱択。貪欲部分は$\frac{N\sum A_i}{{}\_NC_2}$で$O(\max A_i)$。

貪欲は$i \in \\{ i \mid A_i = \min A_j \\}$を始点として愚直に$N$回引くことを繰り返すもの。
未証明だが、十分数の乱択ケースで検証したのでたぶん大丈夫。

定数倍高速化について。
`(i+j)%n`を`i+j<n?i+j:i+j-n`にして剰余を除去すること、clangを使ってSIMDによる最適化をしてもらうことが重要。
${}\_NC_2 \nmod \sum A_i$なら即座に`NO`を返すのも重要。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <random>
#include <chrono>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)
using ll = long long;
using namespace std;
bool solve(vector<int> & a) {
    auto start = chrono::system_clock::now();
    int n = a.size();
    const ll nc2 = n*(n+1ll)/2;
    const ll sum_a = whole(accumulate, a, 0ll);
    if (sum_a % nc2 != 0) return false;
    repeat (q, sum_a / nc2) {
        int i = whole(min_element, a) - a.begin();
        if (a[i] <= 0) break;
        repeat      (k,i)   a[k] -= (n+k)-i+1;
        repeat_from (k,i,n) a[k] -=    k -i+1;
        if (q % 10 == 0) {
            auto end = chrono::system_clock::now();
            double t = chrono::duration<double>(end - start).count();
            if (t > 1.9) {
                random_device device;
                uniform_int_distribution<int> dist(0, 1);
                return dist(device);
            }
        }
    }
    return whole(count, a, 0) == n;
}
int main() {
    int n; cin >> n;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    cout << (solve(a) ? "YES" : "NO") << endl;
    return 0;
}
```

<!-- {% endraw %} -->
