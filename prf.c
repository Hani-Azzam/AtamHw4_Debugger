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
#include <string.h>
#include "elf64.h"
#include <stdbool.h>


///=======================================================================
///==================== Function Address Finder ==========================
///=======================================================================

bool str_cmp(const char* str1, const char* str2){
    while(*str1 && *str2){
        if(*str1 != *str2)
            return false;
        str1++;
        str2++;
    }
    if(*str1 || *str2)
        return false;
    return true;
}

//returns address of desired function, or 0 if its local or not found
Elf64_Addr findFuncAddress(const char* prog_name, const char* func_name){
    FILE* prog_file = fopen(prog_name, "rb"); // open for binary read
    if(!prog_file)
        printf("%s\n", strerror(errno));

    //read elf header, then go to section header array
    Elf64_Ehdr* elf_header = malloc(sizeof(Elf64_Ehdr));
    fread(elf_header, sizeof(Elf64_Ehdr), 1, prog_file);

    ///lets check out .shstrtab wich contains names of sections
    Elf64_Shdr* shstrtab_header = malloc(sizeof(Elf64_Shdr));
    Elf64_Addr offset_to_shstrtab = elf_header->e_shoff + elf_header->e_shstrndx*elf_header->e_shentsize;
    fseek(prog_file, offset_to_shstrtab, SEEK_SET);
    fread(shstrtab_header, sizeof(Elf64_Shdr), 1, prog_file);
    //we found the section. now lets see the strings inside >:)
    char* strings = malloc(shstrtab_header->sh_size*sizeof(char));
    fseek(prog_file, shstrtab_header->sh_offset, SEEK_SET);
    fread(strings, shstrtab_header->sh_size, 1, prog_file);

    //read section header table
    Elf64_Shdr* section_header = malloc(sizeof(Elf64_Shdr));
    //search for symtab and strtab.
    bool symtab_found = false;
    bool strtab_found = false;
    Elf64_Shdr* symtab_header = malloc(sizeof(Elf64_Shdr));
    Elf64_Shdr* strtab_header = malloc(sizeof(Elf64_Shdr));
    for(int i=0; i<elf_header->e_shnum; i++){
        Elf64_Addr offset_to_section = elf_header->e_shoff + i*elf_header->e_shentsize;
        fseek(prog_file, offset_to_section, SEEK_SET);
        fread(section_header, sizeof(Elf64_Shdr), 1, prog_file);
        //printf("\nsecnion %d header name add= %d", i,section_header->sh_name);

        //check the name of section (we want to find symtab and strtab)
        if(str_cmp((strings+section_header->sh_name), ".symtab")){
//            printf("\n####### FOUND symtab #######");
            memcpy(symtab_header, section_header, sizeof(Elf64_Shdr));
            symtab_found = true;
        }
        if(str_cmp((strings+section_header->sh_name), ".strtab")){
//            printf("\n####### FOUND symstr #######");
            strtab_found = true;
            memcpy(strtab_header, section_header, sizeof(Elf64_Shdr));
        }
        //break once both are found
        if(symtab_found && strtab_found)
            break;
    }
    if(!strtab_found || !symtab_found)
        printf("ERROR: A section is missing\n");

    //get the symbol strings
    char* symbol_strings = malloc(strtab_header->sh_size);
    fseek(prog_file, strtab_header->sh_offset, SEEK_SET);
    fread(symbol_strings, strtab_header->sh_size, 1, prog_file);



    //Finally search for symbol entry of our function
    bool found = false;
    Elf64_Sym* symbol_entry = malloc(sizeof(Elf64_Sym));
    for(int i=0; i<(symtab_header->sh_size / symtab_header->sh_entsize); i++){
        Elf64_Addr offset_to_entry = symtab_header->sh_offset + i*symtab_header->sh_entsize;
        fseek(prog_file, offset_to_entry, SEEK_SET);
        fread(symbol_entry, sizeof(Elf64_Sym), 1, prog_file);

        //check the name of Entry (we want to find desired func)
        if(str_cmp((symbol_strings+symbol_entry->st_name), func_name)) {
//            printf("\n####### FOUND THE func symbol entry #######");
            ///TODO: CHECK IF ITS ACTUALY A FUNC AND NOT A VaRIABLE. BY CHecKING IF IT BELONgS
            //TO AN SECTIOn WItH X FLAG (YOU CAN TELL TO WHICH SECTION IT BELOnGS By
            // CHECHING THE NDX OF THE EnTRY)
            found = true;
            break;
        }
    }

    //check if function exists within file
    if(!found){
        printf("PRF:: not found!\n");
        return 0;
    }
    //check if it is local
    if(ELF64_ST_BIND(symbol_entry->st_info) == 0){ //zero means local, one means global
        printf("PRF:: local found!\n");
        return 0;
    }

    Elf64_Addr func_address = symbol_entry->st_value;

    //Free and close
    free(elf_header);
    free(section_header);
    free(shstrtab_header);
    free(strings);
    free(symtab_header);
    free(strtab_header);
    free(symbol_entry);
    free(symbol_strings);
    fclose(prog_file);
    return func_address;
}


///=======================================================================
///============================= DEBUGGER ================================
///=======================================================================

Elf64_Addr place_breakpoint(pid_t child_pid, Elf64_Addr addr);
void remove_breakpoint(pid_t child_pid, Elf64_Addr addr, Elf64_Addr data);

pid_t run_target(const int argc, const char** args)
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
        char *argv [argc+1];
        memcpy(argv, args, argc * sizeof(char*));
        argv[argc] = NULL;
//        printf("- massage from child: about to do execvp with: %s\n", argv[0]);
        int error = execv(argv[0], &argv); //whats best? execv, execp, execcl...
        printf("ERROR: execv failed\n");
        return error;
		
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

    //return;
    while(WIFSTOPPED(wait_status)) {;
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
//        return_address = *(Elf64_Addr*)(regs.rsp); //Top of child's stack contains ret address
        Elf64_Addr return_address = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rsp, NULL);
        ///debug - show stack
//        for(int i=0;i<41;i+=4) {
//            Elf64_Addr lom = ptrace(PTRACE_PEEKTEXT, child_pid, regs.rsp+i, NULL);
//            printf("stack position %d contains: Ox%x = %d\n", i/4, lom, lom);
//        }
        return_instruction = place_breakpoint(child_pid, return_address);

        //Intercept system calls
        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        while(1){
            wait(&wait_status);
            //check if stopped by (entry) syscall and record it. Else break
            if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) & 0x80){ //<<functionality from PTRACE_O_TRACESYSGOOD
                //(stopped by syscall)
                //get address of syscall (Enter-syscall)
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                Elf64_Addr syscall_addr = regs.rip - 2; //subtract 2 because thats the length of syscall command, which the rip skips
                //get output of syscall (from Exit-syscall)
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                long long syscall_return_val = regs.rax; //needs to be signed
                //print about syscall if it failed
                if(syscall_return_val < 0){
                    printf("PRF:: syscall in %x returned with %ld\n", syscall_addr, syscall_return_val);
                }
            } else {
                //was stopped by breakpoint of ret. (*actually could be any other
                // kind of stop, but we assume everything goes well and uninterrupted)
                break;
            }

            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        }


        /*/ The child can continue running now
        //ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);

        //Intercept system calls
        while(1){
            wait(&wait_status);
            //check if stopped by (entry) syscall and record it. Else break
            if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) & 0x80){ //<<functionality from PTRACE_O_TRACESYSGOOD
                //(stopped by syscall)
                //get address of syscall (Enter-syscall)
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                Elf64_Addr syscall_addr = regs.rip - 2; //subtract 2 because thats the length of syscall command, which the rip skips
                //get output of syscall (from Exit-syscall)
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                long syscall_return_val = regs.rax; //needs to be signed
                //print about syscall if it failed
                if(syscall_return_val < 0){
                    printf("PRF:: syscall in %x returned with %ld\n", syscall_addr, syscall_return_val);
                }
            } else {
                //was stopped by breakpoint of ret. (*actually could be any other
                // kind of stop, but we assume everything goes well uninterrupted)
                break;
            }

            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        }*/

        // Remove  return's  breakpoint
        remove_breakpoint(child_pid, return_address, return_instruction);

        //check if finished
        if (WIFEXITED(wait_status))
            break;
    }
}

Elf64_Addr place_breakpoint(pid_t child_pid, Elf64_Addr addr){
    /* Look at the word at the address we're interested in */
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



///===================================================================delete
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
    ///Debugging the debugger
//    char* s2 = "multiple_calls_test.out"; char* s0="ksos";
//    char* s1 = "foo";
//    char** heyyo[3]; heyyo[0]=s0; heyyo[1]=s1; heyyo[2]=s2;
//    argc = 3; argv = heyyo;
    // get desired function address
    Elf64_Addr func_address = findFuncAddress(argv[2], argv[1]);
    if(func_address == 0)
        return 0;
//    printf("Function was found at %d\n", func_address);//hani
    pid_t child_pid;

    child_pid = run_target(argc-2, &argv[2]);

	// run specific "debugger"
	run_hani_debugger(child_pid, argv[1], func_address);
	//run_counter_debugger(child_pid);

    return 0;
}
