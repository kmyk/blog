---
layout: post
redirect_from:
  - /writeup/algo/yukicoder/470/
  - /blog/2016/12/21/yuki-470/
date: "2016-12-21T16:53:52+09:00"
tags: [ "competitive", "writeup", "yukicoder", "2-sat", "strongly-connected-components-decomposition" ]
"target_url": [ "http://yukicoder.me/problems/no/470" ]
---

# Yukicoder No.470 Inverse S+T Problem

pirozさんがwriter。testerをしました。
夜中$3$時半に「🔥作成中🔥ですが」
とtester募集しててつらそうだったが、それなりに余裕持って完成していた。

$2$-satの話は(蟻本に載ってるにもかかわらず)忘れていたので、始めは最大流中心に考えて埋める燃やす問題あたりをぐぐったりしていた。
始めからフローに流れたこともあり探索解を軽く見てしまっており、
実質的に$N \le 52$なので気合いで探索でもなんとかなるかもだが想定解より手間なんだから気にしなくてもよさそう、と思ってたら探索で簡単に通されてた。
testerとしてなんだか申し訳なさがある。

## solution

$2$-satに落とす。文字種$L = 52$に対し$O({(\min \\{ L, N \\})}^2)$。
$2$-satは項数の線形で解けることが知られている。項数は$O(N^2)$で増えるが、$N \gt L$なら常に`Impossible`なので問題ない。

各文字列$U_i$に対し、$\|S_i\| = 1 \land \|T_i\| = 2$と分割することを表わす命題変数$x_i$を用意する。
これら$x_1, x_2, \dots, x_n$の間の制約を考えると、$S_1, S_2, \dots, S_N, T_1, T_2, \dots, T_N$のdistinct制約により両立できないようなliteralの組がいくつかあり、それだけである。
よって両立できないようなliteralの対を列挙して$(l_1 \lor l_2) \land (l_3 \lor l_4) \land \dots \land (l\_{k-1} \lor l_k)$として解けばよい。

$2$-satは強連結成分分解を使って解く。詳しくは蟻本を。

## implementation

``` c++
#include <iostream>
#include <vector>
#include <algorithm>
#include <map>
#include <cassert>
#define repeat(i,n) for (int i = 0; (i) < int(n); ++(i))
#define repeat_from(i,m,n) for (int i = (m); (i) < int(n); ++(i))
using namespace std;

struct strongly_connected_components {
    static pair<int,vector<int> > decompose(vector<vector<int> > const & g) { // adjacent list
        strongly_connected_components scc(g);
        return { scc.k, scc.c };
    }
private:
    int n;
    vector<vector<int> > to, from;
    explicit strongly_connected_components(vector<vector<int> > const & g) : n(g.size()), to(g), from(n) {
        repeat (i,n) for (int j : to[i]) from[j].push_back(i);
        decompose();
    }
    vector<bool> used;
    vector<int> vs;
    void dfs(int i) {
        used[i] = true;
        for (int j : to[i]) if (not used[j]) dfs(j);
        vs.push_back(i);
    }
    int k; // number of scc
    vector<int> c; // i-th vertex in g is in c_i-th vertex in scc-decomposed g
    void rdfs(int i) {
        used[i] = true;
        c[i] = k;
        for (int j : from[i]) if (not used[j]) rdfs(j);
    }
    void decompose() {
        used.clear(); used.resize(n, false);
        repeat (i,n) if (not used[i]) dfs(i);
        used.clear(); used.resize(n, false);
        k = 0;
        c.resize(n);
        reverse(vs.begin(), vs.end());
        for (int i : vs) if (not used[i]) {
            rdfs(i);
            k += 1;
        }
    }
};

vector<bool> twosat(int n, vector<pair<int, int> > const & cnf) {
    vector<vector<int> > g(2*n);
    auto i = [&](int x) { assert (x != 0 and abs(x) <= n); return x > 0 ? x-1 : n-x-1; };
    for (auto it : cnf) {
        int x, y; tie(x, y) = it; // x or y
        g[i(- x)].push_back(i(y)); // not x implies y
        g[i(- y)].push_back(i(x)); // not y implies x
    }
    vector<int> component = strongly_connected_components::decompose(g).second;
    vector<bool> valuation(n);
    repeat_from (x,1,n+1) {
        if (component[i(x)] == component[i(- x)]) { // x iff not x
            return vector<bool>(); // unsat
        }
        valuation[x-1] = component[i(x)] > component[i(- x)]; // use components which indices are large
    }
    return valuation;
}

int main() {
    int n; cin >> n;
    vector<string> s(n); repeat (i,n) cin >> s[i];
    assert (1 <= n and n <= 100000);
    repeat (i,n) {
        assert (s[i].length() == 3);
        for (char c : s[i]) assert ('A' <= c and c <= 'Z' or 'a' <= c and c <= 'z');
    }
    vector<bool> result;
    if (n <= 52) {
        //     x_i : U_i = S + TT
        // not x_i : U_i = SS + T
        vector<pair<int, int> > cnf;
        map<string, vector<int> > used;
        repeat (i,n) {
            int x = i + 1;
            used[s[i].substr(0, 1)].push_back(+ x);
            used[s[i].substr(1, 2)].push_back(+ x);
            used[s[i].substr(0, 2)].push_back(- x);
            used[s[i].substr(2, 1)].push_back(- x);
        }
        for (auto it : used) {
            for (int x : it.second) for (int y : it.second) if (x < y) {
                // cerr << "not " << x << " or " << "not " << y << endl;
                cnf.emplace_back(- x, - y); // not x or not y
            }
        }
        result = twosat(n, cnf);
    }
    if (result.empty()) {
        cout << "Impossible" << endl;
    } else {
        repeat (i,n) {
            if (result[i]) {
                cout << s[i][0] << ' ' << s[i][1] << s[i][2] << endl;
            } else {
                cout << s[i][0] << s[i][1] << ' ' << s[i][2] << endl;
            }
        }
    }
    return 0;
}
```
