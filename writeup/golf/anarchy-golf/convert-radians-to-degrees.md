---
layout: post
alias: "/blog/2016/05/02/anagol-convert-radians-to-degrees/"
date: 2016-05-02T21:03:43+09:00
tags: [ "golf", "writeup", "anagol", "anarchy-golf", "ruby", "perl", "c", "float" ]
"target_url": [ "http://golf.shinh.org/p.rb?Convert+Radians+to+Degrees" ]
---

# Anarchy Golf 948. Convert Radians To Degrees

浮動小数点数が絡むとesolangが軒並み死ぬのでだめ。

## ruby

### 私 37byte

<http://golf.shinh.org/reveal.rb?Convert+Radians+to+Degrees/kimiyuki_1460938908>

``` ruby
$<.map{|l|p (l.to_f*57.2957).round 1}
```

1byte削れず。`Kernel.#loop`[^1]を知らなかったのが敗因。

### teebeeさん, xsotさん, mitchsさん 36byte

-   <http://golf.shinh.org/reveal.rb?Convert+Radians+to+Degrees/teebee_1461023428>
-   <http://golf.shinh.org/reveal.rb?Convert+Radians+to+Degrees/xsot_1461897566>

``` ruby
loop{puts"%.1f".%eval(gets)*57.2957}
```

`%`をmethodとして呼んで順序を制御するテク。

-   <http://golf.shinh.org/reveal.rb?Convert+Radians+to+Degrees/mitchs_1461950017>

``` ruby
loop{p (eval(gets)*57.2957).round 1}
```

きれい。`in `eval': no implicit conversion of nil into String (TypeError)`で止めてるので、`gets.to_f`として1byte削るのはだめ。

## perl

### 29byte

``` perl
printf"%.1f
",$_*57.2957for<>
```

私を含めて$10$人全員がこれを提出。

`57.2957`と`for`との間に空白要らないのはrubyでもそう。haskellですら同様のことが可能だが、syntax highlighterはみな間違える。lexerの都合か。

## c

### 64byte

``` c
main(float x){for(;~scanf("%f",&x);)printf("%.1f\n",x*57.2957);}
```

私を含めて$10$人がこれを提出。

## dc

### tailsさん 30byte

<http://golf.shinh.org/reveal.rb?Convert+Radians+to+Degrees/tails_1462155142>

```
?[rB45.91*1+2/A~rn46Ppr?rdx]dx
```

他が軽かったのでついでに見てみたら、正規表現を微分でもしてるみたいな見ためで興味を引かれた。
正直今までdcはただの電卓だと思っていた。

#### 解読

```
#!/usr/bin/env dc
?
[
    r
    B45.91 * 1 + 2 / A ~ r
    n 46 P p
    r ? r d x
]
d x
```

-   dc is a stack alnguage
-   `?` reads a line and execute it
-   `[ ... ]` pushs the contents as a string object
-   `d` duplicates
-   `x` executes the string
    -   in this case, before executes the code string, duplicates it for the loop/recursion
-   `r` reverses/swaps
-   `B45.91`, `1`, `2`, `A` are numbers.
    -   example: `1AB.0C` becomes a number $211.12 = 1 \cdot 100 + 10 \cdot 10 + 11 \cdot 1 + 0 \cdot 0.1 + 13 \cdot 0.01$.
-   `~` is a divmod
-   `n` prints value without newline, then pop
-   `P` prints a number as an ascii code
-   `p` prints value with newline, without poping

reference: <https://www.gnu.org/software/bc/manual/dc-1.05/html_mono/dc.html>

計算式の具体的な中身は面倒なので読んでないです。

---

# Anarchy Golf 948. Convert Radians To Degrees

[^1]: <http://docs.ruby-lang.org/ja/2.3.0/method/Kernel/m/loop.html>
