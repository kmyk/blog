---
category: blog
layout: post
redirect_from:
    - "/blog/2016/10/18/chainer-fizzbuzz/"
date: "2016-10-19T00:57:49+09:00"
tags: [ "fizzbuzz", "chainer", "neural-network", "machine-learning" ]
---

# Chainerでfizzbuzzを書いた

所用により計算環境等が降ってきたので、機械学習の特にnueral networkで遊ぶことになりました。
以前試したときは単純perceptronやらを実装してみて線形分離可能性のあたりを眺めたぐらいで力尽きたのですが、ある程度の成果物への強制力があるので今回はちゃんとやります。

新しい言語をやるわけなので、とりあえずいつものようにfizzbuzzを書きました。

## 問題設定

nueral networkは当然ながら入出力命令を持たないので、こちらで定義する必要がある。

今回は入力の整数の各bitを$0,1$で与え、出力は`fizz` `buzz`に対応する合計$2$bitとし外側で加工することとした。
つまり単なる割り算の問題である。
以下の図のような形。

[![](/blog/2016/10/19/chainer-fizzbuzz/a.png)](/blog/2016/10/19/chainer-fizzbuzz/a.dot)

他にも選択肢はあるが、公式にあるものより単純な例が欲しいというのが動機のひとつであるため、簡単になるこの形式を選んだ。

## 出力例

以下はいい感じに間違えたり間違えなかったりしている例。
表現力は十分にあるので、数値を十分にして回せば全部正解も可能である。

``` sh
$ ./a.py
1
2
fizz
4
buzz
fizz
7
8
fizz
buzz
11
fizz
13
14
fizzbuzz
16
fizz
fizz
19
buzz
fizzbuzz
22
23
fizz
25
26
fizz
28
fizz
fizz
31
32
fizzbuzz
buzz
buzz
fizz
37
buzz
fizz
40
41
fizz
43
44
fizzbuzz
46
47
fizz
buzz
buzz
fizz
52
53
fizz
buzz
56
fizzbuzz
58
59
fizzbuzz
61
62
fizz
64
buzz
fizz
67
68
fizz
70
71
fizz
73
74
fizz
76
77
fizz
79
buzz
fizz
82
83
fizz
buzz
86
fizzbuzz
88
89
fizzbuzz
91
92
fizz
94
buzz
fizz
97
98
fizz
100
./a.py  262.49s user 349.57s system 389% cpu 2:37.02 total
```

## 参考資料

-   <http://joelgrus.com/2016/05/23/fizz-buzz-in-tensorflow/>
-   <https://gist.github.com/odanado/88af99977871d6f8b371f92209eb9bbe>
-   <https://www.amazon.co.jp/dp/4274219348/>

## 実装

-   chainerなのは性能に関する理由ではない
-   層を減らすと精度がかなり悪くなるため$4$層
-   `optimizers.SGD`と`optimizers.Adam`となら何も考えず後者でよいらしい
-   `F.mean_squared_error`はこの場合`F.sigmoid_cross_entropy`の方が適切のようだが一般性のためそのまま
-   GPUは明示的に指定しない限り使われない

``` python
#!/usr/bin/env python2
from __future__ import print_function
import numpy as np
import chainer # 1.16.0
from chainer import cuda, Variable, optimizers
from chainer import Chain
import chainer.functions as F
import chainer.links as L
import random

def encode(n, bits):
    assert 0 <= n < (1 << bits)
    return np.array([ (n & (1<<i)) != 0 for i in range(bits) ]).astype(np.float32)
def answer(n):
    fizz = (n % 3 == 0)
    buzz = (n % 5 == 0)
    return np.array([ fizz, buzz ]).astype(np.float32)
def decode(var, n):
    fizz, buzz = var
    if fizz > 0.5 and buzz > 0.5:
        return 'fizzbuzz'
    elif buzz > 0.5:
        return 'buzz'
    elif fizz > 0.5:
        return 'fizz'
    else:
        return str(n)

class Model(Chain):
    def __init__(self, bits, unit):
        super(Model, self).__init__(
            l1=L.Linear(bits,unit),
            l2=L.Linear(unit,unit),
            l3=L.Linear(unit,unit),
            l4=L.Linear(unit,2),
        )
    def __call__(self, x, t):
        value = self.forward(x)
        loss = F.mean_squared_error(value, t)
        return loss
    def forward(self, x):
        x = F.relu(self.l1(x))
        x = F.relu(self.l2(x))
        x = F.relu(self.l3(x))
        x = self.l4(x)
        return x

def init(args):
    global xp
    model = Model(args.bits, args.unit)
    if args.gpu >= 0:
        cuda.get_device(args.gpu).use()
        model.to_gpu()
        xp = cuda.cupy
    else:
        xp = np
    optimizer = optimizers.Adam()
    optimizer.setup(model)
    return model, optimizer

def train(model, optimizer, args):
    x_train = []
    t_train = []
    for i in range(args.datasize):
        n = random.randint(101, (1<<args.bits)-1)
        x_train += [ encode(n, args.bits) ]
        t_train += [ answer(n) ]
    for epoch in range(args.epochsize):
        for i in range(0, args.datasize, args.batchsize):
            x = Variable(xp.array(x_train[i : i + args.batchsize]))
            t = Variable(xp.array(t_train[i : i + args.batchsize]))
            optimizer.update(model, x, t)

def run(model, args):
    for n in range(1, 100+1):
        x = Variable(xp.array([ encode(n, args.bits) ]))
        model.zerograds()
        value = model.forward(x)
        print(decode(list(value.data[0]), n))

def main(args):
    model, optimizer = init(args)
    train(model, optimizer, args)
    run(model, args)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--gpu', type=int, default=-1)
    parser.add_argument('--bits', type=int, default=16)
    parser.add_argument('--unit', type=int, default=100)
    parser.add_argument('--datasize', type=int, default=20000)
    parser.add_argument('--batchsize', type=int, default=1000)
    parser.add_argument('--epochsize', type=int, default=1000)
    args = parser.parse_args()
    main(args)
```

-   2016年 10月 21日 金曜日 17:36:14 JST
    -   ちょっと修正
