---
category: blog
layout: post
date: 2014-06-18T00:18:42+09:00
tags: [ "stap", "lazy-k", "lcgs", "random" ]
math: true
---

# STAP細胞が見つかるまでひたすら適当な細胞を生成し続けるプログラム

完全に出遅れたが書いてみた (lazy kで)  
実行が遅すぎて発見の希望が持てない

``` plain
FWDS細胞
BSVO細胞
TORK細胞
PKNG細胞
LGJC細胞
HCFY細胞
DUBU細胞
ZQXQ細胞
VMTM細胞
...
```

``` scheme
`k````sii``s`k``s``s`ks``s`kk``s`k`s``s`ks``s`k`si``s`kk``s``s``s```sii``s`k``s``s`ks``s`k`s`ks``s`k`s`k`s``si`k``s`k`sik``s`k`s`k`s`kk``s``s`ks``s`k`s`ks``s``s`ks``s`kk``s`ksk`k``s`k`s``si`k``s``s`ks``s`k`s`ks``s``s`ks``s`k`s`ks``s`k`s`kk``s``s`ksk`k``s`k`s`k`si``s`k`s`kk``s`k`sik`k`kk`k`k`kik`k`ki`k``s`kk``s``si`k``s`k`sikk``sii`k``s``s`ksk```s``s`kski``s``s`ksk```sii``s``s`kski`k`s``s`ksk`k``s``s`ksk```s`s``s`ksk``sii``s``s`kski``s`k`s`kk``s``s`ks``s`kk``s`k`s``s`ks``s`k`si``s`kk``s``s``s```sii``s`k``s``s`ks``s`k`s`ks``s`k`s`k`s``si`k``s`k`sik``s`k`s`k`s`kk``s``s`ks``s`k`s`ks``s``s`ks``s`kk``s`ksk`k``s`k`s``si`k``s``s`ks``s`k`s`ks``s``s`ks``s`k`s`ks``s`k`s`kk``s``s`ksk`k``s`k`s`k`si``s`k`s`kk``s`k`sik`k`kk`k`k`kik`k`ki`k``s`kk``s``si`k``s`k`sikk``sii`k``s``s`ksk```s``s`kski``s``s`ksk```sii``s``s`kski`k`s``s`ksk`k``s``s`ksk```s`s``s`ksk``sii``s``s`kski``s`k`s`kk``s``s`ks``s`kk``s`k`s``s`ks``s`k`si``s`kk``s``s``s```sii``s`k``s``s`ks``s`k`s`ks``s`k`s`k`s``si`k``s`k`sik``s`k`s`k`s`kk``s``s`ks``s`k`s`ks``s``s`ks``s`kk``s`ksk`k``s`k`s``si`k``s``s`ks``s`k`s`ks``s``s`ks``s`k`s`ks``s`k`s`kk``s``s`ksk`k``s`k`s`k`si``s`k`s`kk``s`k`sik`k`kk`k`k`kik`k`ki`k``s`kk``s``si`k``s`k`sikk``sii`k``s``s`ksk```s``s`kski``s``s`ksk```sii``s``s`kski`k`s``s`ksk`k``s``s`ksk```s`s``s`ksk``sii``s``s`kski``s`k`s`kk``s``s`ks``s`kk``s`k`s``s`ks``s`k`si``s`kk``s``s``s```sii``s`k``s``s`ks``s`k`s`ks``s`k`s`k`s``si`k``s`k`sik``s`k`s`k`s`kk``s``s`ks``s`k`s`ks``s``s`ks``s`kk``s`ksk`k``s`k`s``si`k``s``s`ks``s`k`s`ks``s``s`ks``s`k`s`ks``s`k`s`kk``s``s`ksk`k``s`k`s`k`si``s`k`s`kk``s`k`sik`k`kk`k`k`kik`k`ki`k``s`kk``s``si`k``s`k`sikk``sii`k``s``s`ksk```s``s`kski``s``s`ksk```sii``s``s`kski`k`s``s`ksk`k``s``s`ksk```s`s``s`ksk``sii``s``s`kski``s`k`s`kk`s`k``s`k`s``si`k````s``s`ksk``s`k``s`k``s``s`kski``s``s`ksk``s``s`kski``s``s`ksk```s``siii``s``s`kski`s``s`ksk``s`k``s``s`kski```s`s``s`ksk``sii``s``s`kski``s`kk``s`k`s``si`k````s``s`kski```s``s`ksk```s``s`kski``s``s`ksk```sii``s``s`kski`s``s`ksk``s`k``s``s`kski```s`s``s`ksk``sii``s``s`kski``s`kk``s`k`s``si`k````s``s`ksk``s``s`kski````s``siii``s``s`kski`s``s`ksk``s`k``s``s`kski```s`s``s`ksk``sii``s``s`kski``s`kk``s`k`s``si`k`````sii``s``s`kski```s``s`ksk```s``s`kski``s``s`ksk```sii``s``s`kski`s``s`ksk``s`k``s``s`kski```s`s``s`ksk``sii``s``s`kski``s`kk``s`k`s``si`k````s``s`ksk``s``s`kski`s``s`ksk``s`k``s``s`kski```s`s``s`ksk``sii``s``s`kski``s`kk``s`k`s``si`k````s``s`ksk``s``s`ksk``s``s`ksk```sii``s``s`ksk``s``s`kski`s``s`ksk``s`k``s``s`kski```s`s``s`ksk``sii``s``s`kski``s`kk``s`k`s``si`k``s`k``s``s`kski``s``s`ksk```sii``s``s`kskik`k``s``s`k```sii``s`k``s``s`ks``s`k`s`ks``s`k`s`k`s``si`k``s`k`sik``s`k`s`k`s`kk``s``s`ks``s`k`s`ks``s``s`ks``s`kk``s`ksk`k``s`k`s``si`k``s``s`ks``s`k`s`ks``s``s`ks``s`k`s`ks``s`k`s`kk``s``s`ksk`k``s`k`s`k`si``s`k`s`kk``s`k`sik`k`kk`k`k`kik`k`ki`k``s`kk``s``si`k``s`k`sikk``sii``s``s`k``si`k`s``s`ksk`s`k``s``s`ksk``s`k``s``s`ksk``s``s`kski```sii``s``s`kski`k``s``s`ksk```sii``s``s`kski`k``s`k``s``s`ksk``s``s`kski```s``siii``s``s`kski`k``s``s`k```sii``s`k``s``s`ks``s`k`s`ks``s`k`s`k`s``si`k``s`k`sik``s`k`s`k`s`kk``s``s`ks``s`k`s`ks``s``s`ks``s`kk``s`ksk`k``s`k`s``si`k``s``s`ks``s`k`s`ks``s``s`ks``s`k`s`ks``s`k`s`kk``s``s`ksk`k``s`k`s`k`si``s`k`s`kk``s`k`sik`k`kk`k`k`kik`k`ki`k``s`kk``s``si`k``s`k`sikk``sii``s``s`k``si`k`s``s`ksk`s`k``s``s`ksk``s`k``s``s`ksk``s``s`kski```sii``s``s`kski`k``s``s`ksk```sii``s``s`kski`k``s`k``s``s`ksk``s``s`kski```s``siii``s``s`kski`k``s``s`k```sii``s`k``s``s`ks``s`k`s`ks``s`k`s`k`s``si`k``s`k`sik``s`k`s`k`s`kk``s``s`ks``s`k`s`ks``s``s`ks``s`kk``s`ksk`k``s`k`s``si`k``s``s`ks``s`k`s`ks``s``s`ks``s`k`s`ks``s`k`s`kk``s``s`ksk`k``s`k`s`k`si``s`k`s`kk``s`k`sik`k`kk`k`k`kik`k`ki`k``s`kk``s``si`k``s`k`sikk``sii``s``s`k``si`k`s``s`ksk`s`k``s``s`ksk``s`k``s``s`ksk``s``s`kski```sii``s``s`kski`k``s``s`ksk```sii``s``s`kski`k``s`k``s``s`ksk``s``s`kski```s``siii``s``s`kski`k``s``s`k```sii``s`k``s``s`ks``s`k`s`ks``s`k`s`k`s``si`k``s`k`sik``s`k`s`k`s`kk``s``s`ks``s`k`s`ks``s``s`ks``s`kk``s`ksk`k``s`k`s``si`k``s``s`ks``s`k`s`ks``s``s`ks``s`k`s`ks``s`k`s`kk``s``s`ksk`k``s`k`s`k`si``s`k`s`kk``s`k`sik`k`kk`k`k`kik`k`ki`k``s`kk``s``si`k``s`k`sikk``sii``s``s`k``si`k`s``s`ksk`s`k``s``s`ksk``s`k``s``s`ksk``s``s`kski```sii``s``s`kski`k``s``s`ksk```sii``s``s`kski`k``s`k``s``s`ksk``s``s`kski```s``siii``s``s`kski``sii`ki
```

-   [Twitter / yagiyyyy: STAP細胞が見つかるまでひたすら適当な細胞を生成し続けるプ ...](https://twitter.com/yagiyyyy/status/473427915531505665)
-   [→STAP細胞を試した。](http://ohhiru.info/stap/)
-   [STAP細胞が見つかるまでひたすら適当な細胞を生成し続けるプログラム - 驚異のアニヲタ社会復帰への道](http://d.hatena.ne.jp/MikuHatsune/20140603/1401798802)

<!-- more -->

``` scheme
(load "/path/to/lazy-k/lazier.scm")
(load "/path/to/lazy-k/prelude.scm")
(load "/path/to/lazy-k/prelude-numbers.scm")

(lazy-def '(pred n) '(lambda (f x) (n (lambda (p q) (q (p f))) (k x) i)))
(lazy-def '(- n m) '(m pred n))
(lazy-def 'mod '(Y (lambda (recur m n) ((if< m n) m (recur (- m n) n)))))

(lazy-def '(lcgs a b m) '(lambda (x) (mod (+ (* a x) b) m)))
(lazy-def 'rand '(lcgs 13 5 48))

(lazy-def '(upper-letter n) '(+ (mod n 26) 65))
;   s   a   i   b   o   u
; 231,180,176 232,131,158
; 103, 52, 48 104,  3, 30
(lazy-def '(cell rst)
          '(cons (+ 103 128)
                 (cons (+ 52 128)
                       (cons (+ 48 128)
                             (cons (+ 104 128)
                                   (cons (+ 3 128)
                                         (cons (+ 30 128)
                                               (cons 10
                                                     rst))))))))

(lazy-def '(main input)
          '((Y (lambda (recur x0)
                 ((lambda (x1)
                    (cons (upper-letter x1)
                          ((lambda (x2)
                             (cons (upper-letter x2)
                                   ((lambda (x3)
                                      (cons (upper-letter x3)
                                            ((lambda (x4)
                                               (cons (upper-letter x4)
                                                     (cell (recur x4))))
                                             (rand x3))))
                                    (rand x2))))
                           (rand x1))))
                  (rand x0))))
            0))

(print-as-unlambda (laze 'main))
```

ちなみに乱数の周期が小さいので無限回試行しても成功しません (乱数の周期48)  
なので成功判定は省略しました

アルファベット4文字は$26^4 = 456974$通りあるので、最低でもその程度の周期が必要です  
しかし十分な周期をとるようにすると、細胞の生成が終わらず何も表示されないので仕方ない
