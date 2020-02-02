---
category: blog
layout: post
date: "2016-12-23T23:05:49+09:00"
title: "Chainerで中置記法の数式の計算をさせた"
tags: [ "chainer", "neural-network", "lstm", "machine-learning" ]
---

[前回](https://kimiyuki.net/blog/2016/12/08/chainer-a-plus-b/)を元に、`+` `-` `*` `(` `)`を含む不定形な数式を学習させた。
特に何か劇的に変わったわけではない。

## 結果

データ数$20000$で$50000$epoch後、学習は落ち着いたが飽和し終わってはいないぐらい。
複数桁になる演算はけっこう間違う。
正解と桁ごとに比較して評価としているので、そのような感じに間違えている。
なんだかかわいい。

``` python
>>> 3+4
7
>>> 3*4
12
>>> 11*11
117  (121)
>>> 10+10+10
38  (30)

>>> 100000*10
100100  (1000000)
>>> 12345*20
266800  (246900)
>>> 20*12345
5838650  (246900)

>>> 1*(2+3*4)
14
>>> ((2+3)*4)*5
140  (100)
>>> 2*(3+4*5)+6
54  (52)

>>> 10+7
17
>>> 11+7
18
>>> 12+7
29  (19)
>>> 13+7
22  (20)
>>> 14+7
23  (21)
>>> 15+7
24  (22)
>>> 16+7
23
>>> 17+7
32  (24)
>>> 18+7
39  (25)
>>> 19+7
36  (26)

>>> 12345678
12345678
>>> 1000000007
1000000007
```

## implementation

model: <https://gist.github.com/kmyk/b411307cb27e8bebe5546348a8ca0656>

``` python
#!/usr/bin/env python2
from __future__ import print_function
import numpy as np
import chainer # 1.16.0
from chainer import cuda, Variable, optimizers, serializers
from chainer import Chain
import chainer.functions as F
import chainer.links as L
import sys
import random

input_alphabet = '0123456789+-*()= '
output_alphabet = '0123456789- '
def generate_expr(k, depth=0):
    assert k != 0
    p = random.random()
    if k >= 5 and p < 0.3 and depth != 0:
        l = random.randint(1, k-4)
        r = k - l - 3
        op = random.choice('+-*')
        return '(' + generate_expr(l, depth+1) + op + generate_expr(r, depth+1) + ')'
    elif k >= 3 and p < 0.5 + 0.4 * (depth == 0):
        l = random.randint(1, k-2)
        r = k - l - 1
        op = random.choice('+-*')
        return generate_expr(l, depth+1) + op + generate_expr(r, depth+1)
    else:
        while True:
            l = random.randint(max(1, int(k*0.8)), k)
            s = ''.join([ str(random.randint(0, 9)) for _ in range(l) ])
            if s[0] == '0' and len(s) >= 2:
                continue
            return s
def generate(datasize, k):
    text, value = [], []
    for _ in range(datasize):
        s = generate_expr(k-1)
        assert len(s) <= k-1
        text += [ s ]
        value += [ eval(s) ]
    return text, value
def encode_in(text, k):
    alphabet = np.array(list(input_alphabet))
    text = [ (s + '=').ljust(k, ' ') for s in text ]
    return np.array([[alphabet == c for c in s] for s in text]).astype(np.float32)
def encode_out(value, k):
    text = [ str(x).ljust(k, ' ') for x in value ]
    return np.array([[output_alphabet.index(c) for c in s] for s in text]).astype(np.int32)

class Model(Chain):
    def __init__(self, unit):
        super(Model, self).__init__(
            l1=L.Linear(len(input_alphabet), unit),
            l2=L.LSTM(unit, unit),
            l3=L.Linear(unit, len(output_alphabet)),
        )
    def forward(self, x, k):
        self.l2.reset_state()
        for i in range(x.shape[1]):
            h = F.sigmoid(self.l1( Variable(x[:, i, :]) ))
            h = self.l2(h)
        result = []
        for i in range(k):
            h = F.sigmoid(h)
            h = self.l2(h)
            result += [ self.l3(h) ]
        return result

def init(args):
    global xp
    model = Model(args.unit)
    if args.load is not None:
        serializers.load_npz(args.load, model)
    if args.gpu is not None:
        cuda.get_device(args.gpu).use()
        model.to_gpu()
        xp = cuda.cupy
    else:
        xp = np
    # optimizer = optimizers.Adam()
    optimizer = optimizers.SGD()
    optimizer.setup(model)
    optimizer.add_hook(chainer.optimizer.WeightDecay(0.0001))
    optimizer.add_hook(chainer.optimizer.GradientClipping(5.0))
    return model, optimizer

def train(model, optimizer, args):
    k = args.numbersize
    for epoch in range(args.epochsize):
        if epoch % args.dataepoch == 0:
            text, value = generate(args.datasize, k)
            x_train = encode_in(text, k)
            t_train = encode_out(value, k)
        print('epoch: %d' % epoch)

        sum_accu, sum_loss = 0, 0
        perm = np.random.permutation(args.datasize)
        for i in range(0, args.datasize, args.batchsize):
            indices = perm[i : i + args.batchsize]
            x = xp.array(x_train[indices])
            t = xp.array(t_train[indices])

            y = model.forward(x, k)
            accu, loss = 0, 0
            for i in range(k):
                ti = Variable(t[:, i])
                accu += F.accuracy(y[i], ti)
                loss += F.softmax_cross_entropy(y[i], ti)
            optimizer.zero_grads()
            loss.backward()
            loss.unchain_backward()
            optimizer.update()

            sum_accu += float(accu.data) * len(indices)
            sum_loss += float(loss.data) * len(indices)

        print('train accuracy: %0.3f'   % (sum_accu / args.datasize))
        print('train loss: %0.3f' % (sum_loss / args.datasize))
        for i in range(3):
            j = indices[i]
            print('train example:\t%s\t = %d\t -> %s' % (text[j], value[j], ''.join([ output_alphabet[int(y_.data[i].argmax())] for y_ in y ])))

        testsize = 100
        text_test, value_test = generate(testsize, k)
        x_test = xp.array(encode_in(text_test, k))
        t_test = xp.array(encode_out(value_test, k))
        y = model.forward(x_test, k)
        accu, loss = 0, 0
        for i in range(k):
            ti = Variable(t_test[:, i])
            accu += F.accuracy(y[i], ti)
            loss += F.softmax_cross_entropy(y[i], ti)
        sum_accu = float(accu.data) * testsize
        sum_loss = float(loss.data) * testsize
        print('test accuracy: %0.3f'   % (sum_accu / testsize))
        print('test loss: %0.3f' % (sum_loss / testsize))
        for i in range(3):
            print('test example:\t%s\t = %d\t -> %s' % (text_test[i], value_test[i], ''.join([ output_alphabet[int(y_.data[i].argmax())] for y_ in y ])))
        sys.stdout.flush()

        if (epoch + 1) % args.dataepoch == 0:
            if args.save is not None:
                model.to_cpu()
                serializers.save_npz(args.save, model)
                model.to_gpu()

def main(args):
    model, optimizer = init(args)
    train(model, optimizer, args)

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--gpu', type=int)
    parser.add_argument('--unit', type=int, default=200)
    parser.add_argument('--datasize', type=int, default=20000)
    parser.add_argument('--batchsize', type=int, default=1000)
    parser.add_argument('--epochsize', type=int, default=50000)
    parser.add_argument('--dataepoch', type=int, default=50)
    parser.add_argument('--numbersize', type=int, default=12)
    parser.add_argument('--save')
    parser.add_argument('--load')
    parser.add_argument('-e', '--eval')
    args = parser.parse_args()
    if args.eval:
        if args.load is None:
            parser.error('model is not specified')
        if args.gpu is not None:
            parser.error('gpu is not supported for --eval')
        model = Model(args.unit)
        serializers.load_npz(args.load, model)
        k = args.numbersize
        text = args.eval
        assert len(text) <= k-1
        x = np.array(encode_in([ text ], k))
        y = model.forward(x, k)
        print(''.join([ output_alphabet[int(y_.data[0].argmax())] for y_ in y ]))
        sys.exit(0)
    main(args)
```
