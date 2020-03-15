---
category: blog
layout: post
redirect_from:
    - "/blog/2017/01/31/automate-binary-analysis/"
date: "2017-02-01T01:23:23+09:00"
tags: [ "ctf", "rev", "automation" ]
---

# バイナリ中のalarm関数の呼び出しを自動で除去させてみる

## 設定

与えられたバイナリを直接編集して`alarm`関数の呼び出しを除去する。特にこれを自動で行うプログラムを書く。

例えば次のようなC言語のコードから生成されるバイナリを考える。

``` c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

void handler(int sig) {
    printf("SIGALRM recieved\n");
    exit(1);
}

int main(void) {
    signal(SIGALRM, handler);
    alarm(1);
    system("sleep 2");
    printf("Congratulations!\n");
    return 0;
}
```

これを以下のようにコンパイルすると、`main`関数内である$0x40067d$において`call <alarm@plt>`命令が見つかる。
実行すると`sleep 2`による待機中に`alarm(1);`による`SIGALRM`が発生するため、`Congratulations!`の表示は行なわれず、先に`SIGALRM recieved`が出力され終了する。

この`call <alarm@plt>`を自動で除去し、`Congratulations!`と表示されるように自動で修正させるのが目標である。

``` asm
$ gcc foo.c

$ objdump -d -M intel a.out | grep ' <main>:' -A 16
0000000000400665 <main>:
  400665:	55                   	push   rbp
  400666:	48 89 e5             	mov    rbp,rsp
  400669:	be 46 06 40 00       	mov    esi,0x400646
  40066e:	bf 0e 00 00 00       	mov    edi,0xe
  400673:	e8 a8 fe ff ff       	call   400520 <signal@plt>
  400678:	bf 03 00 00 00       	mov    edi,0x3
  40067d:	e8 7e fe ff ff       	call   400500 <alarm@plt>
  400682:	bf 35 07 40 00       	mov    edi,0x400735
  400687:	e8 64 fe ff ff       	call   4004f0 <system@plt>
  40068c:	bf 3d 07 40 00       	mov    edi,0x40073d
  400691:	e8 4a fe ff ff       	call   4004e0 <puts@plt>
  400696:	b8 00 00 00 00       	mov    eax,0x0
  40069b:	5d                   	pop    rbp
  40069c:	c3                   	ret    
  40069d:	0f 1f 00             	nop    DWORD PTR [rax]

$ ./a.out
SIGALRM recieved
```


## 準備

今回はPython 3で記述し、また以下のふたつのライブラリを用いる。

-   [Capstone](http://www.capstone-engine.org/)
-   [pyelftools](https://github.com/eliben/pyelftools)

Capstoneはdisassemblerであり、pyelftoolsはコンテナであるELFのparserである。

今回は利用しないが、emulationをしたいならUnicorn、assemblerが欲しいならKeystone、PEやMach-Oに対応させたいならpefileやmacholibがよいだろう。

-   [Unicorn](http://www.unicorn-engine.org/)
-   [Keystone](http://www.keystone-engine.org/)
-   [pefile](https://github.com/erocarrera/pefile)
-   [macholib](https://bitbucket.org/ronaldoussoren/macholib)

なおCapstone,Keystone,Unicornは全てC言語+各種bindingsという形であり、Pythonに限らず利用できる。


## 実装

先に実装の全体を示す。
x86/x86_64 ELFの普通のバイナリに対して動く。$80$行とあまり長くない長さである。

``` python
#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
from capstone import *
from capstone.x86 import *

def find_call_alarm(path):
    # load elf
    print('[*] open: %s' % path)
    elf = ELFFile(open(path, 'rb'))

    # load disassembler
    if elf.header.e_machine == 'EM_X86_64':
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif elf.header.e_machine == 'EM_386':
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        assert False
    md.detail = True

    # get alarm@got
    relx_plt = elf.get_section_by_name('.rela.plt') or elf.get_section_by_name('.rel.plt')
    dynsym = elf.get_section_by_name('.dynsym')
    for reloc in relx_plt.iter_relocations():
        symbol = dynsym.get_symbol(reloc.entry.r_info_sym)
        if symbol.name == 'alarm':
            alarm_got = reloc.entry.r_offset
    print('[+] alarm@got = %#x' % alarm_got)

    # guess alarm@plt
    plt = elf.get_section_by_name('.plt')
    for insn in md.disasm(plt.data(), plt.header.sh_addr):
        if insn.mnemonic == 'jmp':
            value = None
            for op in insn.operands:
                if op.type == X86_OP_MEM:
                    if insn.reg_name(op.mem.base) == 'rip' and op.mem.index == 0:
                        value = insn.address + insn.size + op.mem.disp
                    elif op.mem.base == 0 and op.mem.index == 0:
                        value = op.mem.disp
            if value == alarm_got:
                alarm_plt = insn.address
    print('[+] alarm@plt = %#x' % alarm_plt)

    # find all "call alarm@plt"
    xref = []
    text = elf.get_section_by_name('.text')
    for insn in md.disasm(text.data(), text.header.sh_addr):
        if insn.mnemonic == 'call':
            for op in insn.operands:
                value = None
                if op.type == X86_OP_IMM:
                    value = op.imm
                if value == alarm_plt:
                    offset = insn.address - text.header.sh_addr + text.header.sh_offset
                    xref += [ { 'offset': offset, 'length': insn.size } ]
                    print('[*] %#x: call alarm@plt  (offset = %d)' % (insn.address, offset))

    return xref

def overwrite_with_nop(path, xref):
    # overwrite them with "nop"
    print('[*] overwrite: %s' % path)
    with open(path, 'rb+') as fh:
        for it in sorted(xref, key=lambda it: it['offset']):
            fh.seek(it['offset'] - fh.tell())
            fh.write(b'\x90' * it['length'])
    print('[+] done')


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('path', nargs='?', default='a.out')
    args = parser.parse_args()

    xref = find_call_alarm(args.path)
    overwrite_with_nop(args.path, xref)

if __name__ == '__main__':
    main()
```


実行例:

``` asm
$ gcc foo.c

$ objdump -d -M intel a.out | grep ' <main>:' -A 16
0000000000400665 <main>:
  400665:	55                   	push   rbp
  400666:	48 89 e5             	mov    rbp,rsp
  400669:	be 46 06 40 00       	mov    esi,0x400646
  40066e:	bf 0e 00 00 00       	mov    edi,0xe
  400673:	e8 a8 fe ff ff       	call   400520 <signal@plt>
  400678:	bf 01 00 00 00       	mov    edi,0x1
  40067d:	e8 7e fe ff ff       	call   400500 <alarm@plt>
  400682:	bf 35 07 40 00       	mov    edi,0x400735
  400687:	e8 64 fe ff ff       	call   4004f0 <system@plt>
  40068c:	bf 3d 07 40 00       	mov    edi,0x40073d
  400691:	e8 4a fe ff ff       	call   4004e0 <puts@plt>
  400696:	b8 00 00 00 00       	mov    eax,0x0
  40069b:	5d                   	pop    rbp
  40069c:	c3                   	ret    
  40069d:	0f 1f 00             	nop    DWORD PTR [rax]

$ python3 kill-alarm.py
[*] open: a.out
[+] alarm@got = 0x601028
[+] alarm@plt = 0x400500
[*] 0x40067d: call alarm@plt  (offset = 1661)
[*] overwrite: a.out
[+] done

$ objdump -d -M intel a.out | grep ' <main>:' -A 20
0000000000400665 <main>:
  400665:	55                   	push   rbp
  400666:	48 89 e5             	mov    rbp,rsp
  400669:	be 46 06 40 00       	mov    esi,0x400646
  40066e:	bf 0e 00 00 00       	mov    edi,0xe
  400673:	e8 a8 fe ff ff       	call   400520 <signal@plt>
  400678:	bf 01 00 00 00       	mov    edi,0x1
  40067d:	90                   	nop
  40067e:	90                   	nop
  40067f:	90                   	nop
  400680:	90                   	nop
  400681:	90                   	nop
  400682:	bf 35 07 40 00       	mov    edi,0x400735
  400687:	e8 64 fe ff ff       	call   4004f0 <system@plt>
  40068c:	bf 3d 07 40 00       	mov    edi,0x40073d
  400691:	e8 4a fe ff ff       	call   4004e0 <puts@plt>
  400696:	b8 00 00 00 00       	mov    eax,0x0
  40069b:	5d                   	pop    rbp
  40069c:	c3                   	ret    
  40069d:	0f 1f 00             	nop    DWORD PTR [rax]

$ ./a.out
Congratulations!
```

## 解説

実装の詳細について解説する。

### main

始めは`main`関数。
`find_call_alarm`関数で`alarm`の呼び出しを列挙し、これを`overwrite_with_nop`関数で破壊的に潰すという構成。

### find_call_alarm

`find_call_alarm`関数について。

#### header

まずpyelftoolsを用いて`ELFFile(open(path, 'rb'))`とファイルを読み、
その情報から`Cs(CS_ARCH_X86, CS_MODE_64)`等としてCapstoneを呼び出し。
Capstoneは純粋なdisassemblerなので、ELFやPEのようなコンテナには関与しないことに注意。

#### got

次にGOT内での`alarm`のentryのaddressである、`alarm@got`の取得。
これは`.rela.plt`/`.rel.plt`と`.symtab`と`.dynsym`を読めばよい。

`.rela.plt`/`.rel.plt`はrelocation情報のtableである。
`.dynsym`はsymbol table、`.dynstr`はこれから参照される文字列 tableである。
GOTは(`.interp`で指定される)外部のlinkerにより実行時に操作する必要があるため、(実行時には不要な)他のsymbolが格納されている`.symtab`,`.strtab`とは違うsectionとなっている。

`.rel.plt`にあるのは以下のようなaddressとsymbolの対である。`.rela.plt`はここに加数`r_addend`(symbolで引いてきた値に加える値)を加えたもので、併存も可能だが基本的にどちらか一方だけだろう。

``` c
typedef struct {
    Elf64_Addr r_offset;
    uint64_t   r_info;
} Elf64_Rel;
```

これをなめてsymbol `alarm`を指すものの`r_offset`が`alarm@got`である。
pyelftoolsは薄いので自分でそのようになめる。

#### plt

`alarm@plt`の推測。
linkerが動的に操作する必要のあるGOTと違ってその結果を勝手に見に行くだけであるPLTはELF内にsymbolを残す必要がなく、GOTとの対応等から推測する必要がある。

`.plt`内の命令を眺め、`.got.plt`内の`alarm@got`を参照している位置を探すのがよいだろう。
これにはCapstoneを用いる。
emulatorであるUnicornを加えて持ってきてもよいが、今回は対象が固定的なので、`jmp [rip + 0x12345678]`や`jmp ds:0x12345678`の形式をしている命令に関して手で参照先を計算する。
`jmp [$base + $index * scale + disp]`となっている。

#### text

最後に`call <alarm@plt>`を列挙。
`.text`を開いてなめる。

`.plt`での場合と同様に、`call 0x12345678`の形の命令について`alarm@plt`との一致を確認する。

### overwrite_with_nop

これは素直にやる。
実行時のaddressとファイル内でのoffsetを混同しないように注意する。

## 所感

-   自動化は楽しい
-   asmの操作はいいけどELFがつらい

## 資料

ELFについて:

-   [ELFの動的リンク - slideshare, 7shi](http://www.slideshare.net/7shi/startprintf2-elf)
-   [ELF Formatについて - caspar.hazymoon.jp](http://caspar.hazymoon.jp/OpenBSD/annex/elf.html)
