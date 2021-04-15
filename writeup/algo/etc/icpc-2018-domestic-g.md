---
redirect_from:
  - /writeup/algo/etc/icpc-2018-domestic-g/
layout: post
date: 2018-07-10T13:07:00+09:00
tags: [ "competitive", "writeup", "icpc", "parsing", "two-pointers-technique" ]
"target_url": [ "http://icpc.iisf.or.jp/past-icpc/domestic2018/contest/all_ja.html", "http://icpc.iisf.or.jp/past-icpc/domestic2018/judgedata/G/" ]
---

# ACM-ICPC 2018 国内予選: G. 数式探し

## solution

ひたすら丁寧にしゃくとり法をやるだけ。
難しさは3点: 部分文字列の取り出し方によって構文木の形が変わること、`1*`/`*1`の処理、`9*9*9*...*9`のような巨大数の処理。
括弧はかならず対応するので気にしなくてよい。
<span>$O(|S|)$</span>。

構文解析は適当にする。
括弧をちぎるような部分文字列の取り出し方を無視してよいことから式は<span>$a_{11} \cdot a_{12} \cdot \dots \cdot a_{1k_1} + a_{21} \cdot a_{22} \cdot \dots \cdot a_{2k_2} + \dots + a_{k1} \cdot a_{k2} \cdot \dots \cdot a_{kk_k}$</span>という形。
<span>$\left( ( a_{11}, a_{12}, \dots, a_{1k_1} ), ( a_{21}, a_{22}, \dots, a_{2k_2} ), \dots, ( a_{k1}, a_{k2}, \dots, a_{kk_k} ) \right)$</span>のような数列の列が得られる。
加法と乗法だけであることから$n$を越える数は無視してよく、特にその位置で列を分割してよい。
よってすべての<span>$a_{ij} \le n$</span>と仮定できる。
この列の上でしゃくとり法。
<span>$a_{ij} = 1$</span>がないとすれば多少面倒だがやるだけ、あってもさらに面倒なだけでやるだけ。

$n$を越える数は無視してよいというのは気付かなくてもPythonを使えば回避できる。
大嘘ではあるが`__float128`で無理矢理やっても通った。

## implementation

``` c++
#include <bits/stdc++.h>
#define REP(i,n) for (int i = 0; (i) < (n); ++(i))
#define ALL(x) begin(x), end(x)
#define double __float128
#define ll long long
using namespace std;

void count_ranges(int n, vector<vector<double> > const & ast, ll *cnt) {
    // flatten
    vector<double> a, expr, term;
    int size = 0;
    REP (i, ast.size()) {
        REP (j, ast[i].size()) {
            a.push_back(ast[i][j]);
            expr.push_back(i);
            term.push_back(j);
        }
        size += ast[i].size();
    }

    // two-pointers
    int l = 0, r = 0;
    double acc = 0;
    deque<double> deq;
    while (r < size) {
        int k = 0;

        // extend right
        while (r < size and ((l == r ? 0 : acc) < n or (a[r] == 1 and term[r] >= 1))) {
            if (term[r] == 0) {
                deq.push_back(1);
                k = 0;
            } else {
                acc -= deq.back();
            }
            k = a[r] == 1 ? k + 1 : 1;
            deq.back() *= a[r];
            acc += deq.back();
            ++ r;
        }

        // shrink left
        while (l < r and acc >= n) {
            if (acc == n) *cnt += min(k, r - l);
            acc -= deq.front();
            deq.front() /= a[l];
            if (term[l] == ast[expr[l]].size() - 1) {
                deq.pop_front();
            } else {
                acc += deq.front();
            }
            ++ l;
        }
    }
}

double solve_expr(int n, const char **s, ll *cnt);
vector<double> solve_term(int n, const char **s, ll *cnt);
double solve_formula(int n, const char **s, ll *cnt);

double solve_expr(int n, const char **s, ll *cnt) {
    double acc = 0;
    vector<vector<double> > ast;
    while (true) {
        auto it = solve_term(n, s, cnt);
        ast.push_back(it);
        acc += accumulate(ALL(it), 1.0, multiplies<double>());
        if (**s != '+') break;
        ++ *s;
    }
    count_ranges(n, ast, cnt);
    return acc;
}

vector<double> solve_term(int n, const char **s, ll *cnt) {
    vector<double> values;
    while (true) {
        values.push_back(solve_formula(n, s, cnt));
        if (**s != '*') break;
        ++ *s;
    }
    return values;
}

double solve_formula(int n, const char **s, ll *cnt) {
    char c = **s;
    ++ *s;
    if (isdigit(c)) {
        return c - '0';
    } else {
        assert (c == '(');
        double value = solve_expr(n, s, cnt);
        assert (**s == ')');
        ++ *s;
        return value;
    }
}

int main() {
    while (true) {
cerr << "---" << endl;
        int n; cin >> n;
        if (n == 0) break;
        string s; cin >> s;
cerr << "n = " << n << endl;
// cerr << "s = " << s << endl;
        const char *ptr = s.c_str();
        ll cnt = 0;
        solve_expr(n, &ptr, &cnt);
        cout << cnt << endl;
cerr << "answer = " << cnt << endl;
    }
    return 0;
}
```
