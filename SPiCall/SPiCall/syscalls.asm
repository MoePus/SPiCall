.code
     
asm_syscall proc
    mov eax, ecx

    push rsi
    push rdi
    push rcx
    push rdx
    sub rsp,100h

    mov rcx, rdx
    add rcx, 5
    lea rsi, [rsp + 120h]
    mov rdi, rsp
    rep movsq

    cmp edx, 1
    jl skip

    mov r10, r8
    cmp edx, 2
    jl skip

    xchg rdx, r9
    cmp r9d, 3
    jl skip

    mov r8, [rsp + 28h]
    cmp r9d, 4
    jl skip

    mov r9, [rsp + 30h]
skip:
    add rsp, 10h
    syscall
    sub rsp, 10h
    add rsp,100h
    pop rdx
    pop rcx
    pop rdi
    pop rsi
    ret
asm_syscall endp

end