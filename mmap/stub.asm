[bits 64]

;backup registers
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
 
;restore import
mov rax, 0xff00efbeadde00ff
mov rdx, 0xff00dec0adde00ff
mov qword [rax], rdx
xor rax, rax
xor rdx, rdx
 
;prepare dllmain args
sub rsp, 0x28
mov rcx, 0xefbeaddeefbeadde ; hModule
xor rdx, rdx
add rdx, 1
 
mov rax, 0xdec0addedec0adde ; entry point
call rax
add rsp, 0x28
 
;restore registers
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