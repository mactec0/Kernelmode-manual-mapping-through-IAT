[bits 64] 
push rcx 
push rdx  
push rbp
push rsi
push rbx
push rdi
push r8
push r9
push r10
push r11
push r12
push r13
push r14
push r15

sub rsp, 0x28
mov rcx, 0xefbeaddeefbeadde	; hModule
xor rdx, rdx 
add rdx, 1

mov rax, 0xdec0addedec0adde ; entry point
call rax 
add rsp, 0x28 

pop r15
pop r14
pop r13
pop r12
pop r11
pop r10 
pop r9
pop r8
pop rdi
pop rbx
pop rsi
pop rbp
pop rdx 
pop rcx 

xor rax, rax 
ret

 
