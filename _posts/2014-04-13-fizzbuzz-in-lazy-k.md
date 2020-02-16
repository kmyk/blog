---
category: blog
layout: post
date: 2014-04-13T02:27:48+09:00
tags: [ "lazyk", "fizzbuzz", "scheme" ]
---

# lazk kでfizzbuzz書いた

-   妥協してschemeで書いた
-   非常に簡単
-   lazier.scmが強力すぎた
-   `$ grep -c '\<[ski]\>'`すると2 (2行 計3つ)
-   4300byte

``` scheme
(load "/path/to/lazier.scm")
(load "/path/to/prelude.scm")
(load "/path/to/prelude-numbers.scm")

(lazy-def '(ifzero n x y) '(ifnonzero n y x))

(lazy-def '(pred n) '(lambda (f x) (n (lambda (p q) (q (p f))) (k x) i)))
(lazy-def '(- n m) '(m pred n))
(lazy-def 'mod '(Y (lambda (recur m n) ((if< m n) m (recur (- m n) n)))))
(lazy-def 'div '(Y (lambda (recur m n) ((if< m n) 0 (succ (recur (- m n) n))))))

(lazy-def 'map '(Y (lambda (recur f xs) (null? xs () (cons (f (car xs)) (recur f (cdr xs)))))))
(lazy-def 'append '(Y (lambda (recur xs ys) (null? xs ys (cons (car xs) (recur (cdr xs) ys))))))
(lazy-def 'concat '(Y (lambda (recur xs) (null? xs () (append (car xs) (recur (cdr xs)))))))

(lazy-def 'enum-from '(Y (lambda (recur n) (cons n (recur (succ n))))))
(lazy-def '(append-newline x) '(append x (cons 10 ())))

(lazy-def 'fizz '(cons 102 (cons 105 (cons 122 (cons 122 ())))))
(lazy-def 'buzz '(cons 98 (cons 117 (cons 122 (cons 122 ())))))
(lazy-def 'fizzbuzz '(append fizz buzz))

(lazy-def 'num->char '(+ 48))
(lazy-def 'posnum->string
          '(Y (lambda (recur n) ((ifzero n) ()
                                            (append (recur (div n 10)) (cons (num->char (mod n 10)) ()))))))
(lazy-def '(num->string n) '((ifnonzero n) (posnum->string n) (num->char 0)))

(lazy-def '(num->fizzbuzz n) '((ifzero (mod n 15) fizzbuzz
                                       (ifzero (mod n 5) buzz
                                               (ifzero (mod n 3) fizz
                                                       (num->string n))))))

(lazy-def '(main input) '(concat (map (o append-newline num->fizzbuzz) (enum-from 1))))
(print-as-unlambda (laze 'main))
```

---

# lazk kでfizzbuzz書いた

2014/04/17
:   -   Yコンビネータの無駄な再定義を除去
    -   map系関数のnil周りを修正
    -   入力の無視の方法を改良
