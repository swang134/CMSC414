	.file	"task0c.c"
	.text
	.globl	your_fcn
	.type	your_fcn, @function
your_fcn:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	$0, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	your_fcn, .-your_fcn
	.section	.rodata
.LC0:
	.string	"You lose!"
.LC1:
	.string	"You win!"
	.text
	.globl	main
	.type	main, @function
main:
.LFB6:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$48, %rsp
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	xorl	%eax, %eax
	leaq	-32(%rbp), %rax
	movl	$0, %esi
	movq	%rax, %rdi
	call	gettimeofday@PLT
	movq	-24(%rbp), %rax
	movl	%eax, %edi
	call	srand@PLT
	movl	$0, %eax
	call	your_fcn
	movl	%eax, -36(%rbp)
	call	rand@PLT
	movl	%eax, -40(%rbp)
	movl	-40(%rbp), %eax
	cmpl	-36(%rbp), %eax
	jle	.L4
	movl	-36(%rbp), %eax
	subl	$1, %eax
	movl	%eax, -40(%rbp)
.L4:
	movl	-36(%rbp), %eax
	cmpl	-40(%rbp), %eax
	jle	.L5
	leaq	.LC0(%rip), %rdi
	call	puts@PLT
	jmp	.L6
.L5:
	leaq	.LC1(%rip), %rdi
	call	puts@PLT
.L6:
	movl	$0, %eax
	movq	-8(%rbp), %rdx
	xorq	%fs:40, %rdx
	je	.L8
	call	__stack_chk_fail@PLT
.L8:
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	main, .-main
	.ident	"GCC: (Ubuntu 7.4.0-1ubuntu1~18.04.1) 7.4.0"
	.section	.note.GNU-stack,"",@progbits
