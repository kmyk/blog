---
category: blog
layout: post
title: "lisp上で原始再帰的関数で遊べるセット"
date: 2015-06-11T22:16:47+09:00
tags: [ "lisp" ]
---

教科書に出て来たときとか、少しだけ一般的でないプログラミング言語を触るときとか、こういうの欲しくなりますよね。毎回書くのは面倒なのでblogに保存。

``` scheme
(define zero (lambda () 0))
(define succ (lambda (n) (+ n 1)))
(define (pi n) (lambda (x . xs) (if (= n 1) x (apply (pi (- n 1)) xs))))
(define (compose f . gs)
  (lambda args (apply f (map (lambda (g) (apply g args)) gs))))
(define (primitive-recurse f g)
  (let ((init (lambda (xs) (reverse (cdr (reverse xs)))))
        (snoc (lambda (xs x) (append xs (list x)))))
  (letrec ((h (lambda args
                (let ((xs (init args))
                      (n  (last args)))
                  (if (= 0 n)
                    (apply f xs)
                    (apply g (snoc (snoc xs (- n 1)) (apply h (snoc xs (- n 1))))))))))
    h)))
(define cp compose)
(define pr primitive-recurse)
```

<!-- more -->

当然$\mu$演算子もあります。

``` scheme
(define (mu f)
  (let ((snoc (lambda (xs x) (append xs (list x)))))
    (lambda args
      (let loop ((n 0))
        (if (= 0 (apply f (snoc args n)))
          n
          (loop (+ n 1)))))))
```

使用例

``` scheme
(define pr/pred (pr (cp zero) (pi 1)))
(define pr/add (pr (pi 1) (cp    succ (pi 3))))
(define pr/sub (pr (pi 1) (cp pr/pred (pi 3))))
(define pr/mul (pr (cp zero) (cp pr/add (pi 1) (pi 3))))
(define pr/not (pr (cp (cp succ (cp zero))) (cp zero)))
```
