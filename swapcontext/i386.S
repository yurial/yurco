#define oEAX        0x40
#define oECX        0x3c
#define oEDX        0x38
#define oEDI        0x24
#define oESI        0x28
#define oEBP        0x2c
#define oEIP        0x4c
#define oESP        0x30
#define oEBX        0x34
#define oFPREGS     0x60
#define oFPREGSMEM  0xec
#define oFS         0x18


    .text
    .align 4
    .globl yurco_swapcontext
    .type yurco_swapcontext, @function

yurco_swapcontext:
    /* Load address of the context data structure we save in.  */
    movl    4(%esp), %eax

    /* Return value of swapcontext.  EAX is the only register whose
       value is not preserved.  */
    movl    $0, oEAX(%eax)

    /* Save the 32-bit register values and the return address.  */
    movl    %ecx, oECX(%eax)
    movl    %edx, oEDX(%eax)
    movl    %edi, oEDI(%eax)
    movl    %esi, oESI(%eax)
    movl    %ebp, oEBP(%eax)
    movl    (%esp), %ecx
    movl    %ecx, oEIP(%eax)
    leal    4(%esp), %ecx
    movl    %ecx, oESP(%eax)
    movl    %ebx, oEBX(%eax)

    /* Save the FS segment register.  */
    xorl    %edx, %edx
    movw    %fs, %dx
    movl    %edx, oFS(%eax)

    /* We have separate floating-point register content memory on the
       stack.  We use the __fpregs_mem block in the context.  Set the
       links up correctly.  */
    leal    oFPREGSMEM(%eax), %ecx
    movl    %ecx, oFPREGS(%eax)
    /* Save the floating-point context.  */
    fnstenv (%ecx)

    /* Load address of the context data structure we have to load.  */
    movl    8(%esp), %ecx

    /* EAX was modified, reload it.  */
    movl    8(%esp), %eax

    /* Restore the floating-point context.  Not the registers, only the
       rest.  */
    movl    oFPREGS(%eax), %ecx
    fldenv  (%ecx)

    /* Restore the FS segment register.  We don't touch the GS register
       since it is used for threads.  */
    movl    oFS(%eax), %edx
    movw    %dx, %fs

    /* Fetch the address to return to.  */
    movl    oEIP(%eax), %ecx

    /* Load the new stack pointer.  */
    movl    oESP(%eax), %esp

    /* Push the return address on the new stack so we can return there.  */
    pushl   %ecx

    /* Load the values of all the 32-bit registers (except ESP).
       Since we are loading from EAX, it must be last.  */
    movl    oEDI(%eax), %edi
    movl    oESI(%eax), %esi
    movl    oEBP(%eax), %ebp
    movl    oEBX(%eax), %ebx
    movl    oEDX(%eax), %edx
    movl    oECX(%eax), %ecx
    movl    oEAX(%eax), %eax

    /* The following 'ret' will pop the address of the code and jump
       to it.  */

    ret

