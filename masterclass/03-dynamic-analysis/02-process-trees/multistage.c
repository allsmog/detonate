/*
 * multistage.c — training sample for Module 3.2 (process trees & syscalls).
 * BENIGN. Mimics a "dropper -> payload" process shape:
 *   stage0 (this) -> fork -> child -> execve a second program (/bin/echo)
 * so strace -f shows a clone()/clone3() (the fork) followed by an execve() in
 * the child — the raw syscalls Detonate reconstructs into a process tree.
 *
 * Build:  gcc -O2 -no-pie multistage.c -o multistage
 * Trace:  strace -f -e trace=clone,clone3,execve,write ./multistage
 */
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

int main(void) {
    printf("stage0 pid=%d\n", getpid());
    fflush(stdout);

    pid_t pid = fork();            /* -> clone()/clone3() in the trace */
    if (pid == 0) {
        /* child: become a different program -> execve() in the trace */
        execl("/bin/echo", "echo", "stage1-payload-executed", (char *)NULL);
        _exit(127);               /* only reached if execve fails */
    }
    waitpid(pid, NULL, 0);
    printf("stage0 done\n");
    return 0;
}
