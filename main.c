/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <signal.h>
#include <setjmp.h>

#include <unistd.h>
#include <sys/mman.h>

extern char insn_test_proc_code_begin, insn_test_proc_code_end;
extern char insn_ptr_off;
extern char cont_addr;
extern char prev_sp;
unsigned short *insn_ptr;
static unsigned long prev_sp_val;

__attribute__((used, naked))
void insn_test_proc_code()
{
	__asm__("insn_test_proc_code_begin:\n\t"
		"push {r0-r12,lr}\n\t"
		"ldr r0, prev_sp\n\t"
		"str sp, [r0]\n\t"
		"mov r0, #0\n\t"
		"mov r1, #0\n\t"
		"mov r2, #0\n\t"
		"mov r3, #0\n\t"
		"mov r4, #0\n\t"
		"mov r5, #0\n\t"
		"mov r6, #0\n\t"
		"mov r7, #0\n\t"
		"mov r8, #0\n\t"
		"mov r9, #0\n\t"
		"mov r10, #0\n\t"
		"mov r11, #0\n\t"
		"mov r12, #0\n\t"
		"mov lr, #0\n\t"
		"mov sp, r0\n\t" // yup, or we can overwrite something
		"insn_ptr_off:\n\t"
		"nop.w\n\t"
		"cont_addr:\n\t"
		"ldr lr, prev_sp\n\t"
		"ldr sp, [lr]\n\t"
		"pop {r0-r12,pc}\n\t"
		"prev_sp:\n\t"
		".long 0\n\t"
		"insn_test_proc_code_end:\n\t"
		);
}

static void (*insn_test_proc)();
static void (*insn_test_proc2)();
static unsigned long sig_data;
enum sig_ret 
{
	SIGRET_OK,
	SIGRET_ILL,
	SIGRET_ILL_OFFBY2,
	SIGRET_SEGV,
	SIGRET_ILL_OFF,

	SIGRET_OTHER,
} ret;

void try_insn(unsigned long insn)
{
	ret = SIGRET_OK;
	if (insn_test_proc != insn_test_proc2)
	{
		printf("insn_test_proc changed! insn=0x%08lx, insn_test_proc=%p\n", insn, insn_test_proc);
		insn_test_proc = insn_test_proc2;
	}
	insn_ptr[0] = (insn >> 16) & 0xffff;
	insn_ptr[1] = insn & 0xffff;

	*(unsigned long **)((unsigned long)insn_test_proc + (unsigned long)(&prev_sp - &insn_test_proc_code_begin)) = &prev_sp_val;
	mprotect(insn_test_proc, PAGE_SIZE, PROT_READ | PROT_EXEC);
	__builtin___clear_cache((char*)insn_test_proc, (char*) ((unsigned long)insn_test_proc + PAGE_SIZE));
	((void (*)()) ((unsigned long)insn_test_proc+1))();
	mprotect(insn_test_proc, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
	printf(" (0x%08lx) ", insn);

	if (ret == SIGRET_OK)
	{
		printf("OK\n");
	}
	else if (ret == SIGRET_ILL)
	{
		printf("SIGILL\n");
	}
	else if (ret == SIGRET_ILL_OFFBY2)
	{
		printf("SIGILL_OFFBY2\n");
	}
	else if (ret == SIGRET_SEGV)
	{
		printf("SIGSEGV\n");
	}
	else if (ret == SIGRET_ILL_OFF)
	{
		printf("SIGILL OFF:0x%08lx\n", sig_data);
	}
	else
	{
		printf("OTHER\n");
	}
	return;
}

void signal_proc(int signum, siginfo_t *info, void *p)
{
	struct ucontext *ucontext = (struct ucontext *) p;
	unsigned long pc = ucontext->uc_mcontext.arm_pc;

	ucontext->uc_mcontext.arm_pc = (unsigned long)insn_test_proc2 + (unsigned long)(&cont_addr - &insn_test_proc_code_begin);
	if (signum == SIGSEGV)
	{
		ret = SIGRET_SEGV;
		return;
	}
	else if (signum != SIGILL)
	{
		ret = SIGRET_OTHER;
		return;
	}

	if (pc == ((unsigned long)insn_ptr))
	{
		ret = SIGRET_ILL;
		return;
	}
	else if (pc == ((unsigned long)insn_ptr) + 2)
	{
		ret = SIGRET_ILL_OFFBY2;
		return;
	}
	sig_data = pc - (unsigned long)insn_ptr;
	ret = SIGRET_ILL_OFF;
}

int main()
{
	insn_test_proc = (void (*)()) mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	insn_test_proc2 = insn_test_proc;

	memcpy(insn_test_proc, &insn_test_proc_code_begin, &insn_test_proc_code_end - &insn_test_proc_code_begin);
	insn_ptr = (unsigned short *)(((char*)insn_test_proc) + (&insn_ptr_off - &insn_test_proc_code_begin));
	*(unsigned long **)((unsigned long)insn_test_proc + (unsigned long)(&prev_sp - &insn_test_proc_code_begin)) = &prev_sp_val;
	__builtin___clear_cache((char*)insn_test_proc, (char*) ((unsigned long)insn_test_proc + PAGE_SIZE));
	/* THUMB calls are very ugly. */
	((void (*)()) ((unsigned long)insn_test_proc+1))();

	stack_t ss;
	memset(&ss, '\0', sizeof(stack_t));

	ss.ss_sp = mmap(NULL, SIGSTKSZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ss.ss_size = SIGSTKSZ;
	ss.ss_flags = 0;
	if (sigaltstack(&ss, NULL) == -1) {
		perror("sigaltstack");
		return 1;
	}

	struct sigaction act, oldact;
	memset(&act, '\0', sizeof(struct sigaction));
	memset(&oldact, '\0', sizeof(struct sigaction));
	act.sa_sigaction = signal_proc;
	act.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigaction(SIGILL, &act, &oldact);
	sigaction(SIGSEGV, &act, &oldact);
	sigaction(SIGBUS, &act, &oldact);
	sigaction(SIGTRAP, &act, &oldact);
	sigaction(SIGFPE, &act, &oldact);
	
	puts("ARM Opcode Fuzzer initialized");
	/* Only long THUMB opcodes for now. You can easily add 16-bit opcodes,
	 * but I see no reason for this */
	for (unsigned long insn = 0xe8000000; insn < 0xffffffff; ++insn)
	{
		/* Opcodes here are from libopcodes */
		// 0xde01 is recognized as udf #1, which is a trap
		if ((insn & 0xffff) == 0xde01)
		{
			continue;
		}
		// skip ldrs
		else if ((insn & 0xfff00f00) == 0xe8500f00)
		{
			continue;
		}
		else if ((insn & 0xffd000ff) == 0xe9d00000)
		{
			continue;
		}
		else if ((insn & 0xff500000) == 0xe9500000)
		{
			continue;
		}
		else if ((insn & 0xff700000) == 0xe8700000)
		{
			continue;
		}
		// skip strs
		else if ((insn & 0xfff000ff) == 0xe8400000)
		{
			insn = 0xe8500000-1;
			continue;
		}
		else if ((insn & 0xfff00fe0) == 0xe8c00f40)
		{
			continue;
		}
		else if ((insn & 0xfff000f0) == 0xe8c00070)
		{
			continue;
		}
		else if ((insn & 0xffd000ff) == 0xe9c00000)
		{
			continue;
		}
		else if ((insn & 0xff500000) == 0xe9400000)
		{
			continue;
		}
		else if ((insn & 0xff700000) == 0xe8600000)
		{
			continue;
		}
		else if ((insn & 0xfe900f00) == 0xf8100e00)
		{
			continue;
		}
		else if ((insn & 0xfe100000) == 0xf8100000)
		{
			continue;
		}
		else if ((insn & 0xff900f00) == 0xf8000e00)
		{
			continue;
		}
		else if ((insn & 0xff100000) == 0xf8000000)
		{
			continue;
		}
		// skip branches
		else if ((insn & 0xf800d000) == 0xf0008000)
		{
			continue;
		}
		else if ((insn & 0xf800d000) == 0xf0009000)
		{
			continue;
		}
		else if ((insn & 0xf800d000) == 0xf000c000)
		{
			continue;
		}
		else if ((insn & 0xf800d000) == 0xf000d000)
		{
			continue;
		}
		try_insn(insn);
	}
	/* Fixup the loop, as it ends at 0xfffffffe. This is ugly,
	 * and can be rewritten properly with do/while. */
	try_insn(0xffffffff);

	munmap((void*)insn_test_proc, PAGE_SIZE);
	ss.ss_flags = SS_DISABLE;
	sigaltstack(&ss, NULL);
	munmap((void*)ss.ss_sp, SIGSTKSZ);

	return 0;
}
