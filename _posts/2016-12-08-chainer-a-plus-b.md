---
category: blog
layout: post
date: "2016-12-08T18:49:10+09:00"
title: "Chainerで A + B を計算した"
tags: [ "chainer", "neural-network", "lstm", "machine-learning" ]
---

ニューラルネットワークに足し算をさせた。
ただし、$a + b$の形の数式を$10$進数表記文字列として与え、その計算結果を$10$進数表記文字列として結果を受けとる。
時系列データの例が欲しかっただけ。

## memo

-   同じ行列を繰り返し使う単純なRNNより、やはりLSTMの方が性能が出た
-   weight decayやgradient clippingしないと結果が途中で`nan`になった
    -   同じ行列を繰り返し使うので勾配が大きくなりやすく、内部の行列の要素が振動発散するため
-   LSTMで`LSTM.reset_state`を呼び忘れると、状態が内部で爆発しMLE
-   文字列は空白右詰めの固定長vectorとして入力し、空白左詰めの固定長vectorとして出力させた
    -   行列に載せると楽かつ速いため
-   入力し終わってから出力させるが、このときLSTMへの入力は前回の出力をそのまま戻す
    -   零vectorでもよいが、LSTMは自分の直前の出力を必ず覚えてるとは限らないので、前回のを与えると処理の助けになる

また数式処理に関して、

-   一般に数式処理は`+` `-` `*`等ならある形の線形でできる
    -   <https://kimiyuki.net/blog/2016/10/10/jag2016autumn-j/>
-   整数を$10$進数展開するのはけっこう厳しい
-   今回は`+`のみなので、シフトレジスタのような形になっていそう (未確認)

## 出力

```
epoch: 100
train accuracy: 3.629
train loss: 9.481
train example:  4132    + 11    = 4143  -> 1120   
train example:  2555    + 525   = 3080  -> 1120   
train example:  13764   + 2213  = 15977 -> 11200  
test accuracy: 3.510
test loss: 9.818
test example:   2       + 12683 = 12685 -> 115    
test example:   2424    + 419   = 2843  -> 1150   
test example:   16875   + 20878 = 37753 -> 11200 
```

```
epoch: 800
train accuracy: 4.759
train loss: 5.876
train example:  9608    + 61    = 9669  -> 9668   
train example:  7       + 13    = 20    -> 18     
train example:  2       + 35    = 37    -> 37     
test accuracy: 4.760
test loss: 5.995
test example:   2       + 6     = 8     -> 7      
test example:   4       + 56435 = 56439 -> 56444  
test example:   19      + 6128  = 6147  -> 6122   
```

```
epoch: 9999
train accuracy: 6.915
train loss: 0.294
train example:  130     + 64748 = 64878 -> 64878  
train example:  356     + 116   = 472   -> 472    
train example:  28      + 37062 = 37090 -> 37090  
test accuracy: 6.900
test loss: 0.314
test example:   85      + 12    = 97    -> 97     
test example:   77437   + 1516  = 78953 -> 78853  
test example:   16      + 154   = 170   -> 170 
```

## implementation

``` python
#!/usr/bin/env python2
from __future__ import print_function
import numpy as np
import chainer # 1.16.0
from chainer import cuda, Variable, optimizers
from chainer import Chain
import chainer.functions as F
import chainer.links as L
import sys

input_alphabet = '0123456789+= '
output_alphabet = '0123456789 '
def generate(n_data, k):
    a = np.exp(np.random.uniform(np.log(1), np.log(10**k), n_data)).astype(np.int32)
    b = np.exp(np.random.uniform(np.log(1), np.log(10**k), n_data)).astype(np.int32)
    c = a + b
    return a, b, c
def encode_in(a, b, k):
    alphabet = np.array(list(input_alphabet))
    texts = np.array([ '{}+{}='.format(a_, b_).rjust(k, ' ') for a_, b_ in zip(a, b) ])
    return np.array([[alphabet == c for c in s] for s in texts]).astype(np.float32)
def encode_out(c, k):
    texts = np.array([ '{}'.format(c_).ljust(k, ' ') for c_ in c ])
    return np.array([[output_alphabet.index(c) for c in s] for s in texts]).astype(np.int32)

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
            h = F.relu(self.l1( Variable(x[:, i, :]) ))
            h = self.l2(h)
        result = []
        for i in range(k):
            h = F.relu(h)
            h = self.l2(h)
            result += [ self.l3(h) ]
        return result

def init(args):
    global xp
    model = Model(args.unit)
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
    k = args.numbersize+2
    for epoch in range(args.epochsize):
        if epoch % args.dataepoch == 0:
            a, b, c = generate(args.datasize, args.numbersize)
            x_train = encode_in(a, b, 2*args.numbersize+2)
            t_train = encode_out(c, k)
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
            print('train example:\t%d\t+ %d\t= %d\t-> %s' % (a[j], b[j], c[j], ''.join([ output_alphabet[int(y_.data[i].argmax())] for y_ in y ])))
        testsize = 100
        test_a, test_b, test_c = generate(testsize, args.numbersize)
        x = xp.array(encode_in(test_a, test_b, 2*args.numbersize+2))
        t = xp.array(encode_out(test_c, k))
        y = model.forward(x, k)
        accu, loss = 0, 0
        for i in range(k):
            ti = Variable(t[:, i])
            accu += F.accuracy(y[i], ti)
            loss += F.softmax_cross_entropy(y[i], ti)
        sum_accu = float(accu.data) * testsize
        sum_loss = float(loss.data) * testsize
        print('test accuracy: %0.3f'   % (sum_accu / testsize))
        print('test loss: %0.3f' % (sum_loss / testsize))
        for i in range(3):
            print('test example:\t%d\t+ %d\t= %d\t-> %s' % (test_a[i], test_b[i], test_c[i], ''.join([ output_alphabet[int(y_.data[i].argmax())] for y_ in y ])))
        sys.stdout.flush()

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
    parser.add_argument('--epochsize', type=int, default=10000)
    parser.add_argument('--dataepoch', type=int, default=10)
    parser.add_argument('--numbersize', type=int, default=5)
    args = parser.parse_args()
    main(args)
```

---


-   Fri Dec 23 23:37:20 JST 2016
    -   いくらか書き漏らしを追記
