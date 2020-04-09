#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <iostream>

void panic(const char *mess) {
  std::perror(mess);
  std::abort();
}

static void read_cmem(pid_t pid, void *dst, size_t child_src, size_t nbytes) {
  char *cdst = static_cast<char *>(dst);
  size_t nreq = nbytes / sizeof(size_t);
  size_t rem = nbytes % sizeof(size_t);

  for (size_t i = 0; i < nreq; ++i) {
    size_t data =
        ptrace(PTRACE_PEEKDATA, pid, child_src + i * sizeof(size_t), NULL);
    memcpy(cdst, &data, sizeof(size_t));
    cdst += sizeof(size_t);
  }

  if (rem == 0)
    return;

  size_t data =
      ptrace(PTRACE_PEEKDATA, pid, child_src + nreq * sizeof(size_t), NULL);
  memcpy(cdst, &data, rem);
}

int main(int argc, char **argv) {

  if (argc < 2) {
    std::cerr << "Usage: ./mystrace <command< [args...]" << std::endl;
    return 1;
  }

  struct user_regs_struct regs;

  pid_t pid;
  pid = fork();
  if (pid == -1)
    panic("fork");

  if (pid == 0) { // children
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
      panic("children ptrace traceme");
    if (execvp(argv[1], argv + 1) == -1)
      panic("children execvp");
  }

  // parent
  int enter_sys = 0;

  while (1) {
    int status;
    if (wait(&status) == -1)
      panic("wait");
    if (WIFEXITED(status))
      break;

    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
      panic("PTRACE_GETREGS");

    if (!enter_sys && regs.orig_rax == 0x0) {
      std::cout << "read: (" << regs.rdi << ", " << regs.rsi << ", " << regs.rdx
                << ") = " << regs.rax << std::endl;

      size_t len = regs.rdx;
      char *data = new char[len + 1];
      read_cmem(pid, data, regs.rsi, len);
      data[len] = 0;
      std::cout << "data: {" << data << "}" << std::endl;
      delete[] data;

    } else if (!enter_sys && regs.orig_rax == 0x1) {
      std::cout << "write: (" << regs.rdi << ", " << regs.rsi << ", "
                << regs.rdx << ") = " << regs.rax << std::endl;

      size_t len = regs.rdx;
      char *data = new char[len + 1];
      read_cmem(pid, data, regs.rsi, len);
      data[len] = 0;
      std::cout << "data: {" << data << "}" << std::endl;
      delete[] data;
    }

    enter_sys = !enter_sys;

    if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
      panic("PTRACE_SYSCALL");
  }

  return 1;
}
