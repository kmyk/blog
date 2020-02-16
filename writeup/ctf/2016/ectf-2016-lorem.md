---
layout: post
redirect_from:
  - /blog/2016/10/23/ectf-2016-lorem/
date: "2016-10-23T23:49:38+09:00"
tags: [ "ctf", "ectf", "rev", "angr" ]
"target_url": [ "http://www.ectf.in/" ]
---

# ECTF 2016: lorem

Our team, scryptos, solved all problems and got the $1$st place :)
And I solved the 2 of 9 problems.

## problem

It `srand(time(NULL));` and make a flag-like string using `rand()`.
The value of `rand` is used to decide only the execution paths, and the all of values assigned to the flag are hardcoded.

``` sh
$ ./lorem
I think I got the key!!
The key might be::SSdKmNl0qT6%DAV6@"&DsPaPMDQ,,pDNS5C{TmUdEMN|&]XyOO}MWNJD/nth/nTr_%s7G8Ic&Kf_/HR^9{XhjP]}xHX<A?#g5`nGRG/ga{'@+j0\Rhy*2b%t8\V@:IH&$PM`f(7B0?QEsjzUYl>f}-&I^z5;m{e\lM*;t?GuUfn[)#*V,k*z.0W$A4DuNNv(t<]}T9P#7By3fnp[vAWdO=a#h-h(/CHQH.Hr^`"arX/k-Ux0PVa*b=Wt::?!?!
Nope

$ ./lorem
I think I got the key!!
The key might be::SSdKmNl0qT6%DAV6@"&DsPaPMDQ,,pDNS5C{TmUdEMN|&]XyOO}MWNJD/nth/nTr_%s7G8Ic&Kf_/HR^9{XhjP]}xHX<A?#g5`nGRG/ga{'@+j0\Rhy*2b%t8\V@:IH&$PM`f(7B0?QEsjzUYl>f}-&I^z5;m{e\lM*;t?GuUfn[)#*V,k*z.0W$A4DuNNv(t<]}T9P#7By3fnp[vAWdO=a#h-h(/CHQH.Hr^`"arX/k-Ux0PVa*b=Wt::?!?!
Nope

$ ./lorem
I think I got the key!!
The key might be::SSdKmNl0qT6%DAV6@"&DsPaPMDQ,,pDNS5C{TmUdEiN|&]XyOO}MWNJD/nth/nTr_%s7G8Ic&Kf_/HR^={XhjP]}xHX<A?#g5`nGRG/ga{'@+a0\Rhy*2b%t8\V@:IH&$PM`f(7B0?QEnjzUYl>f}-&I^z5;m{e\lM*;t?GuUfn[)#*V,k*z.0W$A4DuNNv(t<]}T9P#7By3fnp[vAWdO=a#h-h(/CHQH.Hr^`"arX/k-Ux0PYa*b=Wt::?!?!
Nope
```

## solution

Enumerate the all possible paths.

To do this efficiently, I hooked the `rand` function and let it returns symbols without any constraints.

``` sh
$ echo 'lorEm_ipsuC_dolor_siT_amet_Fonsecte{ur_adipMscing_elit_seA_do_eiusmod_tZmpor_inciEidunt_ut_labGre_et_dolorE_magna_aliquN_ut_enim_ad_Iinim_venSam_quis_nostrHd_exercitation_AllamcR_laboDisunisi_REt_aliquVp_ex_ea_IomnSdo_coEsiquat_duis_Aute_SruYe_dol}' | tr -cd '{A-Z}'
ECTF{MAZEGENISHARDREVISEASY}
```

## implementation

``` python
#!/usr/bin/env python2
import angr
import simuvex
import hashlib

main = 0x400a48
flag = 0x6380c0
flag_length = 248
correct_hash = '76b4de49a0ac354f14d181b3d4c444846b08ad45a5ddc7f45c165212ded1438c'
p = angr.Project('./lorem')
state = p.factory.blank_state(addr=main)

class time(simuvex.SimProcedure):
    def run(self, t):
        pass
class srand(simuvex.SimProcedure):
    def run(self, seed):
        pass
class rand(simuvex.SimProcedure):
    def run(self):
        print 'rand at', self.state.stack_read(offset=0, length=8)
        return self.state.se.BVS('rand', 32)
class puts(simuvex.SimProcedure):
    def run(self):
        s = self.state.se.any_str(self.state.memory.load(flag, flag_length))
        h = hashlib.sha256(s).hexdigest()
        print h, repr(s)
        if h == correct_hash:
            print 'Yep'
        self.static_exits(0)
p.hook_symbol('time', time)
p.hook_symbol('srand', srand)
p.hook_symbol('rand', rand)
p.hook_symbol('puts', puts)

pathgroup = p.factory.path_group(state)
pathgroup.explore()
```
