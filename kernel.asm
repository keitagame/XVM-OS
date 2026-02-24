[BITS 16]
[ORG 0x1000]

start:
    mov ax, 0xB800
    mov es, ax

    mov di, 0
    mov si, msg

print:
    lodsb
    cmp al, 0
    je halt

    mov ah, 0x0F
    stosw
    jmp print

halt:
    cli
    hlt

msg db "Hello Shinya XVMkernel!", 0
