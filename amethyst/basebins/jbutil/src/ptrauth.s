#if defined(__arm64e__)
.align 4
.global _ptrauth_ia, _ptrauth_ib, _ptrauth_da, _ptrauth_db
.global _autha_xpaci, _autha_xpacd, _authb_xpaci, _authb_xpacd
.global _xpaci, _xpacd, _hash_discriminator

.macro mov64
    movk $0, #((($1)>>48)&0xffff), lsl #48
    movk $0, #((($1)>>32)&0xffff), lsl #32
    movk $0, #((($1)>>16)&0xffff), lsl #16
    movk $0, #((($1)>>00)&0xffff)
.endmacro


_ptrauth_ia:
    xpaci   x0
    pacia   x0, x1
    ret


_ptrauth_ib:
    xpaci   x0
    pacib   x0, x1
    ret


_ptrauth_da:
    xpaci   x0
    pacda   x0, x1
    ret


_ptrauth_db:
    xpaci   x0
    pacdb   x0, x1
    ret


_autha_xpaci:
    mov     x8, x0
    xpaci   x8
    autia   x0, x1
    cmp     x0, x8
    bne     0f
    ret
0:
    mov     x0, xzr
    ret


_autha_xpacd:
    mov     x8, x0
    xpacd   x8
    autda   x0, x1
    cmp     x0, x8
    bne     0f
    ret
0:
    mov     x0, xzr
    ret


_authb_xpaci:
    mov     x8, x0
    xpaci   x8
    autib   x0, x1
    cmp     x0, x8
    bne     0f
    ret
0:
    mov     x0, xzr
    ret


_authb_xpacd:
    mov     x8, x0
    xpacd   x8
    autdb   x0, x1
    cmp     x0, x8
    bne     0f
    ret
0:
    mov     x0, xzr
    ret


_xpaci:
    xpaci   x0
    ret


_xpacd:
    xpacd   x0
    ret


_sip_round:
    add     x0, x0, x1
    lsr     x4, x1, #51
    orr     x1, x4, x1, lsl #13
    eor     x1, x1, x0
    lsr     x4, x0, #32
    orr     x0, x4, x0, lsl #32
    add     x2, x2, x3
    lsr     x4, x3, #48
    orr     x3, x4, x3, lsl #16
    eor     x3, x3, x2
    add     x0, x0, x3
    lsr     x4, x3, #43
    orr     x3, x4, x3, lsl #21
    eor     x3, x3, x0
    add     x2, x2, x1
    lsr     x4, x1, #47
    orr     x1, x4, x1, lsl #17
    eor     x1, x1, x2
    lsr     x4, x2, #32
    orr     x2, x4, x2, lsl #32
    ret


_hash_discriminator:
    sub     sp, sp, #0x40
    stp     x29, x30, [sp, #0x30]
    add     x29, sp, #0x30
    str     x0, [sp]
    mov     x9, xzr
0:
    ldrb    w8, [x0]
    cbz     w8, #16
    add     x0, x0, #1
    add     x9, x9, #1
    b       0b
    str     x9, [sp, #0x10]
    lsl     x8, x9, #56
    str     x8, [sp, #0x18]
    ldr     x8, [sp]
    add     x8, x8, x9
    mov     x1, #8
    udiv    x0, x9, x1
    msub    x0, x0, x1, x9
    sub     x8, x8, x0
    str     x8, [sp, #0x20]
    mov     x9, x8
    ldr     x10, [sp]
    mov64   x0, 0x0a257d1c9bbab1c0
    mov64   x1, 0xb0eef52375ef8302
    mov64   x2, 0x1533771c85aca6d4
    mov64   x3, 0xa0e4e32062ff891c
1:
    cmp     x10, x9
    beq     2f
    ldr     x11, [x10]
    eor     x3, x3, x11
    bl      _sip_round
    bl      _sip_round
    eor     x0, x0, x11
    add     x10, x10, #8
    b       1b
2:
    ldr     x8, [sp, #0x10]
    ldr     x9, [sp, #0x18]
    and     x8, x8, #7
3:
    cbz     x8, 4f
    sub     x8, x8, #1
    mov     x11, #8
    mul     x12, x8, x11
    ldrb    w11, [x10, x8]
    lsl     x11, x11, x12
    orr     x9, x9, x11
    b       3b
4:
    eor     x3, x3, x9
    bl      _sip_round
    bl      _sip_round
    eor     x0, x0, x9
    eor     x2, x2, #0xff
    bl      _sip_round
    bl      _sip_round
    bl      _sip_round
    bl      _sip_round
    eor     x8, x2, x3
    eor     x8, x1, x8
    eor     x8, x0, x8
    mov     x0, x8
    mov     x9, #0xffff
    udiv    x8, x8, x9
    msub    x0, x8, x9, x0
    add     x0, x0, #1
    ldp     x29, x30, [sp, #0x30]
    add     sp, sp, #0x40
    ret
#endif
