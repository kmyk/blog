---
layout: post
alias: "/blog/2017/09/04/twctf-2017-liars-trap/"
date: "2017-09-04T13:34:29+09:00"
tags: [ "ctf", "writeup", "twctf", "crypto", "rsa", "shamirs-secret-sharing", "bruteforce" ]
---

# Tokyo Westerns CTF 3rd 2017: Liar's Trap

<!-- {% raw %} -->

メンバーの契約してる計算資源などを借りて殴る準備をしていたら先に手元で当たりを引いてしまった。
運がよかったっぽい。

## problem

[Shamirの秘密分散法](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)。
$(K, N)$閾値法だが、$N$個中に$L$個の嘘が混じっている。
鯖に繋ぐとそのようなデータが降ってくるので秘密を復元せよ。

## solution

Brute-force。

秘密の復号には多項式補間を使う。
閾値$K = 25$だけの点を集めてそれを全て通る次数が最小の多項式を計算する。
嘘が混じってないかの多項式の補間結果$f$の正当性の確認には、十分多くの他の点$(x, y)$が一致する$f(x) = y$ことを確認すればよい。
$K + 1$点使って補間して次数が$K - 1$であることを見て検証するのは確率上で損をする。

$N$個から勝手に$K$個選んで$L$個ある嘘をひとつも踏まない確率$\frac{{}\_{N-L}C\_K}{{}\_NC\_K} = \mathrm{binomial}(62, 25) / \mathrm{binomial}(100, 25) \approx 6.07 \times 10^{-7}$。
$1.65 \times 10^6$回の試行で成功することが期待できる。

多項式補間を$O(K^3)$でやるとすると$25^3 \cdot 1.65 \times 10^6 \approx 2.58 \times 10^{10}$なのでなんとかならないこともない。
検証にも$O(KL)$かかるが無視できる。
鯖は$30$秒で接続が切れるが、そのたびに再接続すればよいのでこの制限時間は無視できる。
実際にsagemath `PolynomialRing`の`lagrange_polynomial`で書いてみると秒あたり$300$回程度の試行が可能。$90$分程度回せばflagになるのなら十分短かいので待てばよい。

## implementation

sagemathを`pwn.tubes.process.process`で呼び出しつついい感じにする。

memo:

-   次の同様の機会にも使えそう
-   workersのcloseは複数なのでtry-catchしたが`contextlib.ExitStack`とかすべき
-   sagemathの起動が遅いので先に起動しておくなど
-   不慮のerrorが怖いので握り潰し

``` python
#!/usr/bin/env python2
from pwn import * # https://pypi.python.org/pypi/pwntools
import sys
import os

## parameters
P = 115792089237316195423570985008687907853269984665640564039457584007913129639747 # modulus
N = 100 # The number of users
K = 25 # (The degree of the polynomial) - 1
L = 38 # The number of liars

## options
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('host', nargs='?', default='ppc2.chal.ctf.westerns.tokyo')
parser.add_argument('port', nargs='?', default=42453 , type=int)
parser.add_argument('--log-level', default='debug')
parser.add_argument('--sage-script', default='a.sage')
parser.add_argument('--num-threads', default=2, type=int)
args = parser.parse_args()
context.log_level = args.log_level

## run
while True:
    try:
        workers = []
        for _ in range(args.num_threads):
            worker = process([ 'sagemath', args.sage_script ], stderr=sys.stderr)
            workers += [ worker ]
        for worker in workers:
            assert 'ready' == worker.recvline().strip()
        with remote(args.host, args.port) as p:
            user = []
            for i in range(N):
                p.recvuntil('User %d: ' % i)
                user_i = int(p.recvline())
                user += [ user_i ]
            p.recvuntil("What's secret? \n")
            rlist = []
            for worker in workers:
                for user_i in user:
                    worker.sendline(str(user_i))
            while True:
                for worker in workers:
                    if worker.can_recv():
                        secret = int(worker.recvline())
                        p.sendline(str(secret))
                        log.info('%s', p.recvall())
                        sys.exit(os.EX_OK)
                try:
                    p.recv(timeout=0.1)
                except EOFError:
                    break
    except Exception as e:
        print e
    finally:
        for worker in workers:
            worker.close()
```

``` python
#!/usr/bin/env sagemath
from sage.all import *
import itertools
from random import shuffle as random_shuffle
import sys

## Parameters
P = 115792089237316195423570985008687907853269984665640564039457584007913129639747 # modulus
N = 100 # The number of users
K = 25 # (The degree of the polynomial) - 1
L = 38 # The number of liars
R.<x> = PolynomialRing(GF(P))

print 'ready'
points = []
for i in range(N):
    user_i = GF(P)(raw_input())
    points += [ (i + 1, user_i) ]

for i in itertools.count():
    random_shuffle(points)
    f = R.lagrange_polynomial(points[: K])
    denied = 0
    for x, y in points[K :]:
        if f(x) != y:
            denied += 1
            if denied > L:
                break
    else:
        print >> sys.stderr, 'found'
        print >> sys.stderr, f
        print f.coefficients()[0]
        break
    if i % 1000 == 0:
        print >> sys.stderr, 'iteration', i
```

## 実行結果

```
$ ./a.py
[+] Starting local process '/usr/bin/sagemath' argv=['sagemath', 'a.sage'] : Done
[+] Starting local process '/usr/bin/sagemath' argv=['sagemath', 'a.sage'] : Done
[DEBUG] Received 0x6 bytes:
    'ready\n'
[DEBUG] Received 0x6 bytes:
    'ready\n'
[+] Opening connection to ppc2.chal.ctf.westerns.tokyo on port 42453: Done
[DEBUG] Received 0x5a0 bytes:
    '--- Distributed Secret ---\n'
    'User 0: 81150319008277935651190969669213782378172579767382815157805982988728819992206\n'
    'User 1: 11712555490012558886089714254641987873285130609221007180864414830910473851875\n'
    'User 2: 63730717344568907876086325724193290114861305343889640416686199506982018899873\n'
    'User 3: 66766397461503971913832844733723049489193095618663319391332778263232193261357\n'
    'User 4: 82638996802643671737543023348237439555817057572349855415482387999067978356731\n'
    'User 5: 70240109086723286657969138586351499304140843802722151452774961683333964365012\n'
    'User 6: 98497625628627988968440523867397599312872565328340665904352039077473936314627\n'
    'User 7: 16122740533639510438943185226043413199786771566979722609611793614677750557290\n'
    'User 8: 36945603640529079359757649050369886737692682895334891442986567053099133422971\n'
    'User 9: 65544388190508452438984490674749688592697674035792275776355146814172533097313\n'
    'User 10: 81518537191575827367039496057882920866023583343034947918370796881435953162275\n'
    'User 11: 87817338660745849043240772812950586374890772491457345016050817558616520517875\n'
    'User 12: 10516424861752371647340014472744545312651558592566281200888348459406328440156\n'
    'User 13: 80771093250148514662089812673968530273945484362230329643515886003592964990486\n'
    'User 14: 5049873803532529953118671325607512024716607382534373842293970111292242134202\n'
    'User 15: 56000312085477626295163884714875982570949405662276973667933309764126454881275\n'
    'User 16: 92069397866212126588286'

...

[DEBUG] Sent 0x4d bytes:
    '8220802122483356817954269691176257566602927371584327025726217758008456434958\n'
[DEBUG] Sent 0x4e bytes:
    '91932182849279606453521420188291709083625432117098630942570447165997071352429\n'
iteration 0
iteration 0
found
69624823218008388921315805060888208141581825988501473246594270689394450169161*x^24 + 64825073055848227291292694348193758809854906501104559347853076227037391403153*x^23 + 31808109129684417299527507936450302010771854844782383011782158199922227331125*x^22 + 12666869281384521659157298884656507926829151137712447899126621260816705356159*x^21 + 21640542208372067903582837172056664439239331251462253201439737499592337646702*x^20 + 9829356453176815294712267387987855219897167396608323519667877896738510296663*x^19 + 34236329816422036178151957912905500636029769444808071449010532397768197110819*x^18 + 110771620903969556259749942118821452607974718767421055691912391573219821596766*x^17 + 92748409927816854017308634583773270215071392990488041276626649577983209235029*x^16 + 101202385066351133406711815082529273555980359682045061775391263338564855173093*x^15 + 81408988486927615874977618623024025905557143965433485808629839959635887747460*x^14 + 59212838114321546358653549408562895603302506538517130369773568546827821810240*x^13 + 76773541028442642735305238590860243334662973229753940529543002597620868897597*x^12 + 50118826016219124347602984350366761933191885879101290175967417660291962314458*x^11 + 55658973461556436551790370307930826873846432771196618234426089443648821947729*x^10 + 68559093225558574101794018004406524889265750699563937967041101285014658097693*x^9 + 5850846357819829925515053051966387701663303023274354636458618870338886552767*x^8 + 77070114240801487407279837730030838825961179153377510505808185027643964986136*x^7 + 43854269077892311931885860253718848444772912693919556406187462506177074586709*x^6 + 38055456239059329959750665101346473712893179053134588772104107941633575030365*x^5 + 31130704079602104420632307046741960074707171644507123627197478958473556885564*x^4 + 959672696712703270049437238053215023200349134726653557662525631952968771803*x^3 + 57463224607975981727415116112331068042892938545254190753713626264463809075234*x^2 + 92090930618783324495003716760378392451067470415954366988472129961056036406627*x + 107667459642126628678155167126081725752852688200361260853307092404499189992800
[DEBUG] Received 0x4f bytes:
    '107667459642126628678155167126081725752852688200361260853307092404499189992800\n'
[DEBUG] Sent 0x4f bytes:
    '107667459642126628678155167126081725752852688200361260853307092404499189992800\n'
[+] Recieving all data: Done (78B)
[DEBUG] Received 0x4e bytes:
    "OK. I'll give you the flag\n"
    "TWCTF{Error_correction_to_Shamir's_Secret_Sharing}\n"
[*] Closed connection to ppc2.chal.ctf.westerns.tokyo port 42453
[*] OK. I'll give you the flag
    TWCTF{Error_correction_to_Shamir's_Secret_Sharing}
[*] Stopped program '/usr/bin/sagemath'
[*] Stopped program '/usr/bin/sagemath'
------------------------------------------------------------------------
/usr/lib/sagemath/local/lib/python2.7/site-packages/cysignals/signals.so(+0x45f8)[0x7f4d14bc15f8]
/usr/lib/sagemath/local/lib/python2.7/site-packages/cysignals/signals.so(+0x4665)[0x7f4d14bc1665]
/usr/lib/sagemath/local/lib/python2.7/site-packages/cysignals/signals.so(+0x8007)[0x7f4d14bc5007]
/lib/x86_64-linux-gnu/libpthread.so.0(+0x11390)[0x7f4d174e1390]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyObject_Call+0x8)[0x7f4d17741fb8]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyEval_CallObjectWithKeywords+0x47)[0x7f4d177f5137]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyErr_CheckSignals+0xa9)[0x7f4d1783f959]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(Py_MakePendingCalls+0x9a)[0x7f4d177f4c8a]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyEval_EvalFrameEx+0x4fb9)[0x7f4d177fa709]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyEval_EvalCodeEx+0x81c)[0x7f4d177ff00c]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(+0x8762c)[0x7f4d1777462c]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyObject_Call+0x43)[0x7f4d17741ff3]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyObject_CallFunctionObjArgs+0x16f)[0x7f4d17742c0f]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyObject_ClearWeakRefs+0x2d8)[0x7f4d177bb0d8]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(+0x63457)[0x7f4d17750457]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(+0x9be47)[0x7f4d17788e47]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyDict_SetItem+0x67)[0x7f4d1778a937]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(_PyModule_Clear+0x16c)[0x7f4d1778ed9c]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(PyImport_Cleanup+0x419)[0x7f4d17812689]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(Py_Finalize+0xfe)[0x7f4d178248ce]
/usr/lib/sagemath//local/lib/libpython2.7.so.1.0(Py_Main+0x5f4)[0x7f4d1783b464]
/lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0xf0)[0x7f4d17126830]
python(_start+0x29)[0x400759]
------------------------------------------------------------------------
$ Attaching gdb to process id 15922.

Saved trace to /home/user/.sage/crash_logs/crash_1dEuLA.log
------------------------------------------------------------------------
Unhandled SIGSEGV: A segmentation fault occurred.
This probably occurred because a *compiled* module has a bug
in it and is not properly wrapped with sig_on(), sig_off().
Python will now terminate.
------------------------------------------------------------------------

$ 
```

---

# Tokyo Westerns CTF 3rd 2017: Liar's Trap

-   2017年  9月  5日 火曜日 00:56:18 JST
    -   補間結果の検証に関して追記

<!-- {% endraw %} -->
