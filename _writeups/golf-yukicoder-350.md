---
layout: post
redirect_from:
  - /writeup/golf/yukicoder/350/
  - /blog/2016/03/11/yuki-350/
date: 2016-03-11T23:06:13+09:00
tags: [ "competitive", "writeup", "yukicoder", "golf" ]
---

# Yukicoder No.350 d=vt

プロに勝ってるの嬉しい。

## [No.350 d=vt](http://yukicoder.me/problems/737)

### 実装

#### perl 32byte

``` perl
#!perl -p
s/ /*/;$_=1e-6+eval|0
```

`|0`は`int`だったのをtailsさんのを見て直した。
newlineは適当にしていいらしいので`-pl`でなく`-p`。

#### 非golf

``` python
#!/usr/bin/env python3
eps = 1e-6
v, t = map(float,input().split())
print(int(v * t + eps))
```

### 解読

tails氏 perl 35byte

``` perl
<>=~/0.(.*) (.*)/;print $1*$2/1e4|0
```

`<>=~/0.(.*) (.*)/`で$v$の小数部分と$t$をそれぞれ`$1` `$2`にcaptureする。掛けて`1e4`で割って`|0`で整数化。
「小数点以下4桁までかならず表示される。」なのでこれでよい。
