---
layout: post
alias: "/blog/2016/12/30/33c3-ctf-someta2/"
date: "2016-12-30T13:39:44+09:00"
tags: [ "ctf", "writeup", "ppc", "rev", "33c3-ctf", "tmp", "template-meta-programming", "haskell", "competitive", "dp", "binary-search" ]
---

# 33C3 CTF: someta2

I like this.

## problem

A minified code with C++ template meta-programming is given.
Find an integer, which the program accepts.

## solution

At first, use `gcc -E` to expand `#define`s and then `clang-format` to format it.
The result is below.

``` c++
#include <iostream>
using ca = __int128;
template <typename ml, ml ta> struct qu { const static ml dw = ta; };
template <bool vl, ca fy, ca xa> struct fl : fl<(xa * 10 > fy), fy, xa * 10> {};
template <ca fy, ca xa> struct fl<true, fy, xa> { using tg = qu<ca, xa>; };
template <ca fy> using ha = typename fl<(10 > fy), fy, 10>::tg;
template <bool yj, bool fk, ca ta, ca ls, ca af, ca lm>
    struct vo : vo < af<10, ta % lm == ls, ta / 10, ls, af / 10, lm> {};
template <bool fk, ca ta, ca ls, ca af, ca lm>
struct vo<true, fk, ta, ls, af, lm> {
  using tg = qu<bool, false>;
};
template <ca ta, ca ls, ca af, ca lm> struct vo<false, true, ta, ls, af, lm> {
  using tg = qu<bool, true>;
};
template <ca ta, ca ls>
using qe = typename vo <
           ha<ta>::dw<ha<ls>::dw, false, ta, ls, ha<ta>::dw, ha<ls>::dw>::tg;
template <bool ao, ca ta, ca... gg> struct di { using tg = qu<bool, ao>; };
template <bool ao, ca ta, ca scq, ca... gg>
struct di<ao, ta, scq, gg...> : di<ao | qe<ta, scq>::dw, ta, gg...> {};
template <ca ta, ca... gg> using zw = typename di<false, ta, gg...>::tg;
template <ca pl> struct uo {
  const static ca dw = uo<pl - 1>::dw + uo<pl - 2>::dw;
};
template <> struct uo<0> { const static ca dw = 0; };
template <> struct uo<1> { const static ca dw = 1; };
template <ca pl> struct yk {
  const static ca dw = yk<pl - 1>::dw + uo<pl>::dw;
};
template <> struct yk<0> { const static ca dw = 0; };
template <ca pl> struct vr {
  const static ca dw = vr<pl - 1>::dw + yk<pl>::dw;
};
template <> struct vr<0> { const static ca dw = 0; };
template <ca pl> struct hp {
  const static ca dw = hp<pl - 1>::dw + vr<pl>::dw;
};
template <> struct hp<0> { const static ca dw = 0; };
template <ca nz, ca xa, ca ta, ca... gg>
struct ww : ww<nz - 1, xa + !zw<ta, gg...>::dw, ta + 1, gg...> {};
template <ca xa, ca ta, ca... gg> struct ww<0, xa, ta, gg...> {
  using tg = qu<ca, xa>;
};
template <ca u, ca... gg> struct np {
  using tg = typename ww<u + 1, 0, 0, gg...>::tg;
};
template <ca, typename> struct uk {};
template <ca ml, ca... ho, template <ca...> class zp> struct uk<ml, zp<ho...>> {
  using tg = zp<ho..., ml>;
};
template <ca u, ca ke, ca nz, template <ca...> class zp> struct eo {
  using tg =
      typename uk<hp<ke>::dw, typename eo<u, ke + 1, nz - 1, zp>::tg>::tg;
};
template <ca u, ca ke, template <ca...> class zp> struct eo<u, ke, 0, zp> {
  using tg = zp<u>;
};
template <ca u, ca ma> using sr = typename eo<u, 0, ma + 1, np>::tg::tg;
template <ca ma> struct lm {
  using tg = qu<bool, sr<ma, 88>::dw == 6089463947169320ull>;
};
template <int nk> struct nu {
  static const int pl = nk;
  int a[pl];
};
template <typename ny> struct jl;
template <> struct jl<qu<bool, true>> { template <int nk> using wg = nu<nk>; };
template <> struct jl<qu<bool, false>> { static const int wg = 0; };
int main() { jl<lm<FLAG>::tg>::wg<1>(); }
```

Next, decode it by your hand.
C++ template meta-programming seems a purely functional-programming language, so I recommend to translate it to Haskell.

``` haskell
ceil10 b = go (10 > b) b 10 where
    go False b c = go (c * 10 > b) b (c * 10)
    go  True b c = c

subint c d = go (ceil10 c < ceil10 d) False c d (ceil10 c) (ceil10 d) where
    go  True     _ c d e f = False
    go False  True c d e f =  True
    go False False c d e f = go (e < 10) (c `mod` f == d) (c `div` 10) d (e `div` 10) f

-- anySubint y zs = go False y zs where
--     go x y [] = x
--     go x y (z : zs) = go (x || subint y z) y zs
anySubint y zs = any (subint y) zs

fib0 = 0 : 1 : zipWith (+) fib0 (tail fib0)
fib1 = 0 :     zipWith (+) fib1 (tail fib0)
fib2 = 0 :     zipWith (+) fib2 (tail fib1)
fib3 = 0 :     zipWith (+) fib3 (tail fib2)

-- countNotSuperInt n zs = go (n+1) 0 0 zs where
--     go 0 x y zs = x
--     go n x y zs = go (n-1) (x + fromEnum (not (anySubint y zs))) (y+1) zs
countNotSuperInt n zs = go (n+1) 0 0 where
    go 0 x y = x
    go n x y = go (n-1) (x + fromEnum (not (anySubint y zs))) (y+1)

-- func x z = go x 0 (z+1) [] where
--     go x y 0 acc = countNotSuperInt x acc
--     go x y z acc = go x (y+1) (z-1) (fib3 !! y : acc)
func x z = go 0 (z+1) [] where
    go y 0 acc = countNotSuperInt x acc
    go y z acc = go (y+1) (z-1) (fib3 !! y : acc)

-- isFlag flag = func flag 88 == 103371362  -- someta1
isFlag flag = func flag 88 == 6089463947169320  -- someta2
```

Here, you may be able to get the flag for someta1.
For someta2, you must speedup the calculation.

## sub-problem

### statement

Let $\phi_k(n)$ for an integer $n$ iff: for all $0 \le i \le k$, let $s$ be the decimal representation of $i$, $s$ is not a substring of the decimal representation of $n$.
Then define $f(n,k) = |\{ x \le n \mid \phi_k(x) \}|$.
Find a $x$ such that $f(\mathrm{x}, 88) = 6089463947169320$.

### solution

Use DP on digits and binary search. It seems $O(\log Q \cdot \log\_{10}Q K^2)$ for $Q = 6089463947169320$.
If you properly classify integers, the number of states doesn't exceed $\sum_i \log\_{10} \mathrm{fib'''}(i)$.

### implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <array>
#include <set>
#include <map>
#include <tuple>
#include <cassert>
#include <experimental/optional>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define whole(f,x,...) ([&](decltype((x)) whole) { return (f)(begin(whole), end(whole), ## __VA_ARGS__); })(x)

using ll = __int128;
using namespace std;
using namespace std::experimental;
ll fib(int n) {
    static vector<ll> memo { 0, 1 };
    static array<ll, 4> a = { { 0, 0, 0, 0 } };
    static array<ll, 4> b = { { 1, 1, 1, 1 } };
    while (memo.size() <= n) {
        array<ll, 4> c;
        c[0] = a[0] + b[0]       ;
        c[1] =        b[1] + c[0];
        c[2] =        b[2] + c[1];
        c[3] =        b[3] + c[2];
        memo.push_back(c[3]);
        a = b; b = c;
    }
    return memo[n];
}
set<ll> fib_list(ll k) {
    set<ll> acc;
    for (ll i = 0; i <= k; ++ i) {
        acc.insert(fib(i));
    }
    return acc;
}
string to_string(ll value) {
    string s;
    while (value) { s += value % 10 + '0'; value /= 10; }
    if (s.empty()) s += '0';
    reverse(s.begin(), s.end());
    return s;
}
// const ll func_flag_88 = 103371362; // someta1
const ll func_flag_88 = 6089463947169320; // someta2

bool is_prefix(string const & prefix, string const & a) {
    if (prefix.size() > a.size()) return false;
    repeat (i, prefix.size()) if (prefix[i] != a[i]) return false;
    return true;
}
bool is_suffix(string const & a, string const & suffix) {
    if (a.size() < suffix.size()) return false;
    int offset = a.size() - suffix.size();
    repeat (i, suffix.size()) if (a[offset + i] != suffix[i]) return false;
    return true;
}
ll solve(ll x, ll k) {
    string upper = to_string(x);
    vector<string> forbidden; for (ll x : fib_list(k)) forbidden.push_back(to_string(x));
    auto is_valid = [&](string const & s) {
        return whole(all_of, forbidden, [&](string const & suffix) { return not is_suffix(s, suffix); });
    };
    auto shrink = [&](string s) {
        while (not s.empty() and whole(all_of, forbidden, [&](string const & suffix) { return not is_prefix(s, suffix); })) {
            s = s.substr(1);
        }
        return s;
    };
    optional<string> border = make_optional("");;
    map<string, ll> prv;
    for (char b : upper) {
        map<string, ll> cur;
        cur[""] += 1;
        for (char c = '0'; c <= '9'; ++ c) {
            if (border and c <= b) {
                string s = *border + c;
                if (is_valid(s)) {
                    if (c < b) {
                        cur[shrink(s)] += 1;
                    } else {
                        assert (c == b);
                        *border = s;
                    }
                } else {
                    if (c == b) border = optional<string>();
                }
            }
            for (auto it : prv) {
                string s; ll cnt; tie(s, cnt) = it;
                s += c;
                if (is_valid(s)) cur[shrink(s)] += cnt;
            }
        }
        prv = cur;
    }
    ll result = 0;
    result -= 1; // for the empty string
    if (border) result += 1;
    for (auto it : prv) {
        string s; ll cnt; tie(s, cnt) = it;
        result += cnt;
    }
    return result;
}

int main() {
    ll l = 0, r = ll(1)<<64; // [l, r)
    while (l + 1 < r) {
        ll m = (l + r) / 2;
        (solve(m, 88) <= func_flag_88 ? l : r) = m;
    }
    cout << to_string(l) << endl;
    return 0;
}
```
