## Manual mapping x64 without creating any threads

This edited version instead of using IAT table uses swapchain VMT table from GameOverlayRenderer64.dll

Stub doesn't call orginal function after executing dllmain, it may sometimes cause some issues.

#### Usage:
```cpp
//offset from 10.29.2019
uint64_t vmt_function_ptr = read_ptr(proc->get_module_base("GameOverlayRenderer64.dll"), { 0x01884C8, 0xe0, 0x00 });
```

swapchain signature [48 39 0D ? ? ? ? 75 16 48 C7 05 ? ? ? ? ? ? ? ? 48 C7 05]
```assembly
40 53                                   push    rbx
48 83 EC 30                             sub     rsp, 30h
48 C7 44 24 20 FE FF FF+                mov     [rsp+38h+var_18], 0FFFFFFFFFFFFFFFEh
48 8B D9                                mov     rbx, rcx
48 8D 05 77 AB 06 00                    lea     rax, off_180119A20
48 89 01                                mov     [rcx], rax
48 39 0D 15 96 0D 00                    cmp     cs:swpchain, rcx
75 16                                   jnz     short loc_1800AEECB
48 C7 05 08 96 0D 00 00+                mov     cs:swpchain, 0
48 C7 05 05 96 0D 00 00+                mov     cs:qword_1801884D0, 0
```
![](https://i.imgur.com/jI6rXmd.png)

</br></br>
