#define _NSIG8      8

#define oRBX        0x80
#define oRBP        0x78
#define oR12        0x48
#define oR13        0x50
#define oR14        0x58
#define oR15        0x60
#define oRDI        0x68
#define oRSI        0x70
#define oRDX        0x88
#define oRCX        0x98
#define oR8     0x28
#define oR9     0x30
#define oRIP        0xa8
#define oRSP        0xa0
#define oFPREGSMEM  0x1a8
#define oFPREGS     0xe0
#define oMXCSR      0x1c0

    .text
    .align 4
    .globl yurco_swapcontext
    .type yurco_swapcontext, @function

yurco_swapcontext:
    /* Save the preserved registers, the registers used for passing args,
       and the return address.  */
    movq    %rbx, oRBX(%rdi)
    movq    %rbp, oRBP(%rdi)
    movq    %r12, oR12(%rdi)
    movq    %r13, oR13(%rdi)
    movq    %r14, oR14(%rdi)
    movq    %r15, oR15(%rdi)

    movq    %rdi, oRDI(%rdi)
    movq    %rsi, oRSI(%rdi)
    movq    %rdx, oRDX(%rdi)
    movq    %rcx, oRCX(%rdi)
    movq    %r8, oR8(%rdi)
    movq    %r9, oR9(%rdi)

    movq    (%rsp), %rcx
    movq    %rcx, oRIP(%rdi)
    leaq    8(%rsp), %rcx       /* Exclude the return address.  */
    movq    %rcx, oRSP(%rdi)

    /* We have separate floating-point register content memory on the
       stack.  We use the __fpregs_mem block in the context.  Set the
       links up correctly.  */
    leaq    oFPREGSMEM(%rdi), %rcx
    movq    %rcx, oFPREGS(%rdi)
    /* Save the floating-point environment.  */
    fnstenv (%rcx)
    stmxcsr oMXCSR(%rdi)

    /* Restore the floating-point context.  Not the registers, only the
       rest.  */
    movq    oFPREGS(%rsi), %rcx
    fldenv  (%rcx)
    ldmxcsr oMXCSR(%rsi)

    /* Load the new stack pointer and the preserved registers.  */
    movq    oRSP(%rsi), %rsp
    movq    oRBX(%rsi), %rbx
    movq    oRBP(%rsi), %rbp
    movq    oR12(%rsi), %r12
    movq    oR13(%rsi), %r13
    movq    oR14(%rsi), %r14
    movq    oR15(%rsi), %r15

    /* The following ret should return to the address set with
    getcontext.  Therefore push the address on the stack.  */
    movq    oRIP(%rsi), %rcx
    pushq   %rcx

    /* Setup registers used for passing args.  */
    movq    oRDI(%rsi), %rdi
    movq    oRDX(%rsi), %rdx
    movq    oRCX(%rsi), %rcx
    movq    oR8(%rsi), %r8
    movq    oR9(%rsi), %r9

    /* Setup finally  %rsi.  */
    movq    oRSI(%rsi), %rsi

    /* Clear rax to indicate success.  */
    xorl    %eax, %eax

    ret

