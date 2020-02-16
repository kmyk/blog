---
category: blog
layout: post
date: 2016-01-07T03:07:09+09:00
tags: [ "asm", "lifegame" ]
---

# アセンブリ言語でlifegameを書いた

気合いで書きました。

なんの変哲もないlifegameなのでそれ単体ではあまり面白くないですが、以前[befungeで書いた](http://kimiyuki.net/blog/2015/08/21/lifegame-in-befunge/)ものと見比べると少し面白いかもしれません。

<!-- more -->

### 実行

``` sh
$ nasm -f elf32 a.asm
$ ld -m elf_i386 a.o
$ ./a.out
```

### 実装

``` asm
section .rodata
    h   equ 25
    w   equ 80
    swapped_space db 0x1b, "[7m", " ", 0x1b, "[0m", 0x0
    table db 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, \
             0, 0, 0, 1, 1, 0, 0, 0, 0, 0

section .bss
buf:
    resb h*w

section .text
global _start

putc:
    push ebp
    mov ebp, esp
    sub esp, 0x4
    mov eax, [esp + 0xc]
    mov [esp], al
    mov eax, 0x4 ; write
    mov ebx, 1 ; stdout
    mov ecx, esp
    mov edx, 1
    int 0x80
    leave
    ret

strlen:
    push ebp
    mov ebp, esp
    xor eax, eax
    mov ebx, [esp + 0x8]
.loop:
    mov cl, [ebx]
    test cl, cl
    je .break
    inc eax
    inc ebx
    jmp .loop
.break:
    leave
    ret

putstr: ; puts without newline
    push ebp
    mov ebp, esp
    push dword [esp + 0x8]
    call strlen
    mov edx, eax
    mov ecx, [esp]
    mov ebx, 1 ; stdout
    mov eax, 0x4 ; write
    int 0x80
    leave
    ret

sleep:
    push ebp
    mov ebp, esp
    sub esp, 0x8
    mov eax, [esp + 0x10]
    mov dword [esp], eax
    mov dword [esp + 0x4], 0
    mov eax, 0xa2 ; nanosleep
    mov ebx, esp
    mov ecx, 0x0 ; NULL
    int 0x80
    leave
    ret

_start:
    mov eax, 0x37 ; fcntl
    mov ebx, 0 ; stdin
    mov ecx, 3; F_GETFL
    int 0x80

    mov edx, eax
    mov eax, 0x37 ; fcntl
    mov ebx, 0 ; stdin
    mov ecx, 4 ; F_SETFL
    or edx, 04000 ; O_NONBLOCK
    int 0x80

    call init
    call initscr

.loop:
    mov eax, 0x3 ; read
    mov ebx, 0 ; stdin
    push 0
    mov ecx, esp ; buf
    mov edx, 1
    int 0x80
    pop ebx

    cmp eax, 1
    je .break ; if read

    ; main process
    call print
    call update

    push 1
    call sleep
    add esp, 0x4
    jmp .loop

.break:
    mov eax, 1 ; exit
    mov ebx, 0 ; EXIT_SUCCESS
    int 0x80


init:
    push ebp
    mov ebp, esp
    sub esp, 0x8

    rdtsc
    xor ecx, ecx
.loop:
    cmp ecx, h*w
    je .break

    ; set buf[y][x]
    xor ebx, ebx
    test eax, 0x00100000
    je .skip
    inc ebx
.skip:
    mov [buf + ecx], ebx

    ; update random, linear congruential generator
    mov edx, 134775813 ; Borland Delphi, Virtual Pascal, https://en.wikipedia.org/wiki/Linear_congruential_generator#Parameters_in_common_use
    mul edx
    inc eax

    inc ecx
    jmp .loop

.break:
    leave
    ret


initscr:
    push ebp
    mov ebp, esp
    push 0
.loop:
    mov eax, [esp]
    cmp eax, h-1
    je .break
    inc eax
    mov [esp], eax

    push 0xa ; newline
    call putc
    add esp, 0x4

    jmp .loop

.break:
    leave
    ret

update:
    push ebp
    mov ebp, esp
    sub esp, h*w + 0x18

    mov dword [ebp - 4], 0
.loop_i:

    mov eax, [ebp - 4]
    xor edx, edx
    mov ebx, w
    div ebx
    mov [ebp - 12], eax ; y
    mov [ebp - 16], edx ; x

    xor ecx, ecx
    mov dword [ebp - 8], 0
.loop_j:

    mov eax, [ebp - 8]
    xor edx, edx
    mov ebx, 3
    div ebx
    dec eax
    dec edx
    add eax, [ebp - 12] ; y'
    add edx, [ebp - 16] ; x'

    mov [ebp - 20], eax ; y'
    mov [ebp - 24], edx ; x'

    cmp eax, -1
    jne .skip_uf_y
    mov eax, h-1
.skip_uf_y:
    cmp eax, h
    jne .skip_of_y
    mov eax, 0
.skip_of_y:
    mov [ebp - 20], eax

    mov eax, [ebp - 24] ; x'
    cmp eax, -1
    jne .skip_uf_x
    mov eax, w-1
.skip_uf_x:
    cmp eax, w
    jne .skip_of_x
    mov eax, 0
.skip_of_x:
    mov [ebp - 24], eax

    mov eax, [ebp - 20]
    mov ebx, w
    mul ebx
    add eax, [ebp - 24]
    xor ebx, ebx
    add bl, [buf + eax] ; count
    add ecx, ebx

    mov eax, [ebp - 8]
    inc eax
    mov [ebp - 8], eax
    cmp eax, 9
    jne .loop_j
.done_j:

    mov eax, [ebp - 4]
    xor ebx, ebx
    mov bl, [buf + eax]
    mov eax, 10
    mul ebx
    add eax, ecx
    mov eax, [table + eax]
    mov ebx, [ebp - 4]
    add ebx, esp
    mov [ebx], al

    mov eax, [ebp - 4]
    inc eax
    mov [ebp - 4], eax
    cmp eax, h*w
    jne .loop_i

.done_i:
    mov ecx, h*w
    mov esi, esp
    mov edi, buf
    pushf
    rep movsb
    popf

    leave
    ret


print:
    push ebp
    mov ebp, esp

    push 0x1b ; <esc>
    call putc
    mov byte [esp], 0x5b ; [
    call putc
    add esp, 0x4

    xor edx, edx
    mov eax, h-1
    mov ebx, 10
    div ebx
    add edx, 0x30
    add eax, 0x30
    push edx
    cmp eax, 0x30
    je .skip
    push eax
    call putc ; h / 10
    add esp, 0x4
.skip:
    call putc ; h % 10
    mov byte [esp], 0x46 ; F
    call putc
    add esp, 0x4

    push -1
.loop:
    mov eax, [esp]
    inc eax
    mov [esp], eax

    mov bl, [buf + eax]
    test bl, bl
    je .else
    push swapped_space
    call putstr
    add esp, 0x4
    jmp .fi
.else:
    push 0x20 ; <space>
    call putc
    add esp, 0x4
.fi:

    mov eax, [esp]
    cmp eax, h*w-1
    je .break

    xor edx, edx
    mov ebx, w
    div ebx
    cmp edx, w - 1
    jne .next
    push 0xa ; newline
    call putc
    add esp, 0x4
.next:

    jmp .loop

.break:
    leave
    ret
```

### 参考

コメント代わりに後から書いたコード。

``` c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#define H 25
#define W 80
#define repeat(i,n) for (int (i) = 0; (i) < (n); ++(i))

bool buf[H][W];

void init() {
    srand(time(NULL));
    unsigned a = rand();
    repeat (y,H) {
        repeat (x,W) {
            buf[y][x] = (bool)(a & 0x00100000);
            a = a * 134775813 + 1;
        }
    }
}
void initscr() {
    repeat (y,H-1) {
        putchar('\n');
    }
}

void print() {
    printf("\x1b[%dF", H-1);
    repeat (i,H*W) {
        int y = i / W;
        int x = i % W;
        if (buf[y][x]) {
            printf("\x1b[7m \x1b[0m");
        } else {
            putchar(' ');
        }
        if (y != H-1 && x == W-1) putchar('\n');
    }
}
const bool table[2][9] =
    { { 0,0,0,1,0,0,0,0,0 }
    , { 0,0,0,1,1,0,0,0,0 } };
void update() {
    bool tmp[H][W];
    repeat (i,H*W) {
        int y = i / W;
        int x = i % W;
        int count = 0;
        repeat (j,9) {
            int dy = j / 3 - 1;
            int dx = j % 3 - 1;
            int ny = (y + dy + H) % H;
            int nx = (x + dx + W) % W;
            if (buf[ny][nx]) {
                count += 1;
            }
        }
        tmp[y][x] = table[buf[y][x]][count];
    }
    repeat (y,H) {
        repeat (x,W) {
            buf[y][x] = tmp[y][x];
        }
    }
}

int main(void) {
    fcntl(STDIN_FILENO, F_SETFL, fcntl(STDIN_FILENO, F_GETFL) | O_NONBLOCK);
    init();
    initscr();
    char c;
    while (read(STDIN_FILENO, &c, 1) != 1) {
        print();
        update();
        sleep(1);
    }
    exit(0);
}
```

