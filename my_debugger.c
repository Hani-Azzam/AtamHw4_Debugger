/* Code sample: using ptrace for simple tracing of a child process.
**
** Note: this was originally developed for a 32-bit x86 Linux system; some
** changes may be required to port to x86-64.
**
** Eli Bendersky (http://eli.thegreenplace.net)
** This code is in the public domain. Now it belongs to Hani hahaha!
*/
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>

typedef uint64_t	Elf64_Addr;

pid_t run_target(const argc, const char* args)
{
	pid_t pid;
	
	pid = fork();
	
    if (pid > 0) {
		return pid;
		
    } else if (pid == 0) {
		/* Allow tracing of this process */
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
			perror("ptrace");
			exit(1);
		}
		/* Replace this process's image with the given program */
        char *args [argc+1];
        memcpy(args, argv, argc * sizeof(char*));
        args[argc] = NULL;
        return execvp(args[0], args);
		
	} else {
		// fork error
		perror("fork");
        exit(1);
    }
}

void run_hani_debugger(pid_t child_pid, char* func_name, Elf64_Addr func_address)
{
    int wait_status;
    struct user_regs_struct regs;
    Elf64_Addr original_instruction, return_instruction,  return_address;

    // Wait for child to stop on its first instruction
    wait(&wait_status);

    // Set option to make it easier for us to distinguish types of ptrace stops
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD);

    while(WIFSTOPPED(wait_status)) {
        //place breakpoint at the function's address
        original_instruction = place_breakpoint(child_pid, func_address);
        // Let the child run till the breakpoint and wait for it to reach it
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status);
        // Remove Breakpoint from function
        remove_breakpoint(child_pid, func_address, original_instruction);
        // Check if child has finished and exited
        if (WIFEXITED(wait_status))
            break;
        // Add new Breakpoint to return address of function
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        return_address = *regs.rsp; //Top of child's stack contains ret address
        return_instruction = place_breakpoint(child_pid, return_address);
        // The child can continue running now
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);

        //Intercept system calls
        while(1){
            wait(&wait_status);
            //check if stopped by (entry) syscall and record it. Else break
            if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80){ //<<functionality from PTRACE_O_TRACESYSGOOD
                //(stopped by syscall)
                //get address of syscall (Enter-syscall)
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                Elf64_Addr syscall_addr = regs.rip;
                //get output of syscall (from Exit-syscall)
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                long syscall_return_val = regs.rax; //needs to be signed
                //print about syscall if it failed
                if(syscall_return_val < 0){
                    printf("PRF:: syscall in %lu returned with %ld\n", syscall_addr, syscall_return_val);
                }
            } else {
                //was stopped by breakpoint of ret. (*actually could be any other
                // kind of stop, but we assume everything goes well uninterrupted)
                break;
            }

            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        }
        // Remove  return's  breakpoint
        remove_breakpoint(child_pid, return_address, return_instruction);
    }
}

Elf64_Addr place_breakpoint(pid_t child_pid, Elf64_Addr addr){
    /* Look at the word at the address we're interested in */
    Elf64_Addr addr = 0x4000cd;
    Elf64_Addr data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);

    /* Write the trap instruction 'int 3' into the address */
    Elf64_Addr data_trap = (data & 0xFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);

    /* Return original data (original instruction) */
    return data;
}
void remove_breakpoint(pid_t child_pid, Elf64_Addr addr, Elf64_Addr data){
    struct user_regs_struct regs;

    /* See where the child is now */
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

    /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
}
///------------------------------------------------------------------delete

void run_breakpoint_debugger(pid_t child_pid)
{
    int wait_status;
    struct user_regs_struct regs;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);

    /* Look at the word at the address we're interested in */
    Elf64_Addr addr = 0x4000cd;
    Elf64_Addr data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
    printf("DBG: Original data at 0x%x: 0x%x\n", addr, data);

    /* Write the trap instruction 'int 3' into the address */
    Elf64_Addr data_trap = (data & 0xFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);

    /* Let the child run to the breakpoint and wait for it to reach it */
    ptrace(PTRACE_CONT, child_pid, NULL, NULL);

    wait(&wait_status);
    /* See where the child is now */
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    printf("DBG: Child stopped at RIP = 0x%x\n", regs.rip);

    /* Remove the breakpoint by restoring the previous data and set rdx = 5 */
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data);
    regs.rip -= 1;
	regs.rdx = 5;
    ptrace(PTRACE_SETREGS, child_pid, 0, &regs);

    /* The child can continue running now */
    ptrace(PTRACE_CONT, child_pid, 0, 0);

    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        printf("DBG: Child exited\n");
    } else {
        printf("DBG: Unexpected signal\n");
    }
}

void run_syscall_debugger(pid_t child_pid)
{
    int wait_status;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    
	struct user_regs_struct regs;
	/* Enter next system call */
	ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
	wait(&wait_status);
	
	ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
	regs.rdx = 5;
	ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

	/* Run system call and stop on exit */
	ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
	wait(&wait_status);
	
	ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
	printf("DBG: the syscall returned: %d\n", regs.rax);
	
	/* The child can continue running now */
    ptrace(PTRACE_CONT, child_pid, 0, 0);
    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        printf("DBG: Child exited\n");
    } else {
        printf("DBG: Unexpected signal\n");
    }
}

void run_regs_override_debugger(pid_t child_pid)
{
    int wait_status;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        struct user_regs_struct regs;
		
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
		regs.rdx = 5;
		ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }
}

void run_instruction_debugger(pid_t child_pid)
{
    int wait_status;
    int icounter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        icounter++;
        struct user_regs_struct regs;
		
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        Elf64_Addr instr = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rip, NULL);

        printf("DBG: icounter = %u.  RIP = 0x%x.  instr = 0x%08x\n",
                    icounter, regs.rip, instr);

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }
}

void run_counter_debugger(pid_t child_pid)
{
    int wait_status;
    int icounter = 0;

    /* Wait for child to stop on its first instruction */
    wait(&wait_status);
    while (WIFSTOPPED(wait_status)) {
        icounter++;

        /* Make the child execute another instruction */
        if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
            perror("ptrace");
            return;
        }

        /* Wait for child to stop on its next instruction */
        wait(&wait_status);
    }

    printf("DBG: the child executed %d instructions\n", icounter);
}

///----------------------------------------------------Above to be deleted

int main(int argc, char** argv)
{
    /// @todo - Find the address of the function to watch
    Elf64_Addr func_address = 0;


    pid_t child_pid;

    child_pid = run_target(argc-2, argv[2]);
	
	// run specific "debugger"
	run_hani_debugger(child_pid, argv[1], func_address);

    return 0;
}