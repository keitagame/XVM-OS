[BITS 16]
[ORG 0x7C00]

start:
    mov ax, 0x07C0
    add ax, 288
    mov ss, ax
    mov sp, 4096

    ; カーネルをメモリに読み込ませる
    mov ah, 2
    mov al, 10        ; 読み込むセクタ数
    mov ch, 0
    mov dh, 0
    mov cl, 2
    mov bx, 0x1000
    int 0x13

    jmp 0x0000:0x1000

times 510-($-$$) db 0
dw 0xAA55
