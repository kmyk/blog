---
layout: post
redirect_from:
  - /writeup/algo/codeforces/601-b/
  - /blog/2015/11/25/cf-601-b/
date: 2015-11-25T04:11:50+09:00
tags: [ "competitive", "writeup", "codeforces", "sequence", "interval" ]
---

# Codeforces Round #333 (Div. 1) B. Lipshitz Sequence

少しだけ発想力がいるかも。実装軽いし解けたので楽しかった。

ところで、今回のこどふぉは[猫](http://codeforces.com/blog/entry/21490)が居る。かわいい。

<!-- more -->

## [B. Lipshitz Sequence](http://codeforces.com/contest/601/problem/B) {#b}

### 問題

数列$h[1\dots n]$から整数への関数$L(h)$を、

$$ \begin{array}{ll}
    L(h) = 0 & (n = 1) \\
    L(h) = \max \lceil \frac{|h_j - h_i|}{j - i} \rceil & (otherwise)
\end{array} $$

で定める。

数列$a[1\dots n]$が与えられる。$q$個($q \le 100$)の以下のようなクエリに答えよ。

閉区間$\left[l, r\right]$が与えられる。部分列$s = a[l\dots r]$とする。
この数列$s$の連続する部分列$s[i\dots j]$($l \le i \le j \le r$)$に関して、それら全ての$L$による像の総和$\Sigma\_{i,j} L(s[i\dots j])$を求めよ。

### 解法

関数$L$の性質より、隣接する2項のみ見ればよい。

長さ3の数列$s = a, a+b, a+b+c$を考えれば、隣接する2項に関して$L(s[1,2]) = b$, $L(s[2,3]) = c$、連続する3項に関して$L(s[1,2,3]) = \lceil \frac{b+c}{2} \rceil$となる。
このとき、$L(s[1,2]) \lt L(s[1,2,3])$かつ$L(s[2,3]) \lt L(s[1,2,3])$はありえない。連続する4項以上に関しても同様なので、隣接する2項のみでよい。

与えられた数列$a_i$の差の列を$b_i = a\_{i+1} - a_i$とする。
$\Sigma\_{l \le i \le j \le r} \max b[i\dots j]$を求めればよい。
これは、区間をまとめながら、右端$j$に関して左から順に見ていくことで求められる。

最大値$m$を持つ区間が$n$個存在する、という形の表を持っておき、右端$j$と共に更新していく。
この表中の全ての区間の右端が$j-1$であるとき、右端を$j$とひとつ右にずらした表を作る。
これは、最大値$m$が$b_j$より小さい区間の全てを最大値が$b_j$である区間にまとめ、$b_j$のみからなる区間を足したものである。
各時点の表中の区間の全てに関してその最大値と個数の積を足し合わせれば、これは全ての連続する部分列の最大値の総和になる。

この操作はstackを上手く使うことで実装できる。
stackへのpushの回数は高々$n$回となるので$1$回のクエリにつき$O(n)$であり、$1$回のクエリに関して$O(n)$、全体で$O(nq)$。

### 実装

本番は`stack`の代わりにorderedな`map`を使った。
後から皆が`stack`と言っているのを聞いて書き直した。

``` c++
#include <iostream>
#include <vector>
#include <stack>
#define repeat(i,n) for (int i = 0; (i) < (n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < (n); ++(i))
typedef long long ll;
using namespace std;
struct intervals_t {
    int max;
    ll count;
};
int main() {
    int n, q; cin >> n >> q;
    vector<int> a(n); repeat (i,n) cin >> a[i];
    vector<int> b(n-1); repeat (i,n-1) b[i] = abs(a[i+1] - a[i]);
    repeat (qi,q) {
        int l, r; cin >> l >> r; -- l; -- r; // [l, r) on b
        ll result = 0;
        ll acc = 0;
        stack<intervals_t> stk;
        repeat_from (i,l,r) {
            ll cnt = 0;
            while (not stk.empty() and stk.top().max <= b[i]) {
                cnt += stk.top().count;
                acc -= stk.top().max * stk.top().count;
                stk.pop();
            }
            stk.push((intervals_t){ b[i], cnt + 1 });
            acc += b[i] * (cnt + 1);
            result += acc;
        }
        cout << result << endl;
    }
    return 0;
}
```


---

# Codeforces Round #333 (Div. 1) B. Lipshitz Sequence

問題のタイトルは綴り間違えているぽい。問題文中は全て正しくLipschitzになってる。
