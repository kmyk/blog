---
category: blog
layout: post
date: 2015-06-12T23:27:18+09:00
math: true
tags: [ ]
---

# 素数列をcplで

cplでなにか複雑なもの、これが書けたのでまあcpl使えますと言える程度のものを書こうと思って、素数列を書きました。

ベルトラン・チェビシェフの定理

>    自然数 $n \ge 2$ に対して、$n \lt p \le 2n$ を満たす素数 $p$ が存在する

というのがあるらしいので、その証明は理解しないままに利用。

<!-- more -->

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

left object list(A) with fold is
    nil: 1 -> list
    cons : prod(A, list) -> list
end object;

left object bool with if is
    true:  1 -> bool
    false: 1 -> bool
end object;

left object maybe(A) with unmaybe is
    nothing: 1 -> maybe
    just:    A -> maybe
end object;

right object inflist(A) with unfold is
    get  : inflist -> A
    next : inflist -> inflist
end object;

let first(f) = prod(f,I);
let singleton = cons.pair(I,nil.!);
let swap = pair(pi2,pi1);
let comp = cur(ev.pair(pi1.pi1,ev.pair(pi2.pi1,pi2)));

let head = fold(nothing.!,just.pi1);
let last = fold(nothing.!,ev.pair(unmaybe(cur(just.pi2),cur(just.pi1)).pi2,pi1));
let snoc = ev.prod(fold(cur(pi2),comp.prod(cur(cons),I)),cons.pair(I,nil.!));
let range = pi1.pr(pair(nil,o),pair(snoc,s.pi2));
let map = ev.prod(fold(cur(nil.!),cur(cons.pair(ev.pair(pi2,pi1.pi1),ev.pair(pi2.pi1,pi2)))),I).swap;

let and = ev.prod(if(cur(pi2),cur(false.!.pi2)),I);
let or  = ev.prod(if(cur( true.!.pi2),cur(pi2)),I);
let not = if(false,true);

let all = fold(true.!,and).map;
let any = fold(false.!,or).map;
let filter = ev.first(fold(cur(nil.!),cur(ev.pair(if(cur(cons.pi2),cur(pi2.pi2)).ev.pair(pi2,pi1.pi1),pair(pi1.pi1,ev.pair(pi2.pi1,pi2)))))).swap;

let pred = pi2.pr(pair(o,o),pair(s.pi1,pi1));
let add = ev.prod(pr(cur(pi2),cur(   s.ev)),nat);
let sub = ev.prod(pr(cur(pi2),cur(pred.ev)),nat).swap;

let zeroq = pr(true,false.!);
let eq = and.prod(zeroq,zeroq).pair(sub,sub.swap);
let gt = and.prod(not.zeroq,zeroq).pair(sub,sub.swap);
let ge = or.pair(gt,eq);

let divmod = ev.pair(pr(cur(pair(o.!,pi1).pi2),cur(ev.pair(if(cur(pair(s.pi1.pi1,sub.pair(pi2.pi1,pi2.pi2)).pi2),cur(pi1.pi2)).ge.pair(pi2.pi1,pi2.pi2),I).pair(ev,pi2))).s.pi1,I);
let div = pi1.divmod;
let mod = pi2.divmod;
let divided = eq.pair(I,o.!).mod;

let head_or_zero = unmaybe(o.!,I).head;
let last_or_zero = unmaybe(o.!,I).last;
let n_plus_one_to_two_n = map.pair(cur(s.add),range);
let prime_with_all = all.first(cur(not.divided));
let get_next_prime = head_or_zero.filter.pair(cur(prime_with_all.swap),n_plus_one_to_two_n.head_or_zero);
let primes = unfold(head_or_zero,cons.pair(get_next_prime,I)).singleton.s.s.o;
```

```
# 2 3 5 7 11
# 5th prime is 11
> simp full get.next.next.next.next.primes
s.s.s.s.s.s.s.s.s.s.s.o
    : 1 -> nat
# 21st prime is 73
> simp full get.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.primes
s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.s.o
    : 1 -> nat
```

上記の21番目の素数を求めるのには、私の環境で26秒程でした。そういう言語ではないのでしかたない。
