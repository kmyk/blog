---
category: blog
layout: post
title: "ackermann関数をcplで"
date: 2015-06-12T23:27:30+09:00
tags: [ "cpl", "ackermann-function" ]
---

ackermann関数は高階原始帰納的関数なので関数空間を使えば書ける[^1][^2]、というのを幾つか見たので気になって書いた。特に高度なことではなかった。

高階関数を許す原始帰納法で定義される関数を高階原始帰納的関数と呼ぶ[^3]ようです。

```
right object 1 with ! is
end object;

right object prod(A,B) with pair is
    pi1: prod -> A
    pi2: prod -> B
end object;

right object exp(A,B) with cur is
    ev: prod(exp, A) -> B
end object;

left object nat with pr is
    o: 1 -> nat
    s: nat -> nat
end object;

let swap = pair(pi2,pi1);
let first(f) = prod(f,I);
let second(f) = prod(I,f);
let comp = cur(ev.pair(pi1.pi1,ev.pair(pi2.pi1,pi2)));
let fpow = ev.first(pr(cur(cur(pi2)),cur(comp.pair(ev,pi2)))).swap;
let ack = ev.first(pr(cur(s.pi2),cur(ev.pair(I,s.o.!).fpow.second(s))));
```

<!-- more -->

---

-   Sun Jun 21 00:30:20 JST 2015
    -   fpowの無駄な`!`を消去
    -   図書きました <https://twitter.com/a3VtYQo/status/612245917668749312> <https://pbs.twimg.com/media/CH8iZ65UAAAjKqT.jpg:orig>

---

[^1]: <http://ci.nii.ac.jp/naid/110003743564>
[^2]: <http://msakai.jp/d/?date=20030114>
[^3]: <http://d.hatena.ne.jp/m-a-o/20091101%2523p2#c1260809763>
