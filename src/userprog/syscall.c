#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "filesys/off_t.h"

static void syscall_handler (struct intr_frame *);
static void sys_halt(void);
static void sys_exit(int status);
static tid_t sys_exec(const char *cmd_line);
static int sys_wait(tid_t tid);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove(const char *file);
static int sys_open(const char *file);
static int sys_filesize(int fd);
static int sys_read(int fd, void *buffer, unsigned size);
static int sys_write(int fd, void *buffer, unsigned size);
static void sys_seek(int fd, unsigned position);
static unsigned sys_tell(int fd);
static void sys_close(int fd);
void check_valid_address(void *esp, int args);

struct file 
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void
sys_halt(void){
  shutdown_power_off();
}

void
sys_exit(int status){
  struct thread *thr = thread_current();
  thr->exit_status = status;
  printf("%s: exit(%d)\n",thr->name, status);
  thread_exit();
}

tid_t 
sys_exec(const char *cmd_line){
  tid_t child_pid = process_execute(cmd_line);
  struct thread *child = find_child(child_pid);
  sema_down(&child->load_sema);
  if(child->load == false)
    return -1;
  
  if(!child){
     return -1;
   }

  return child_pid;
}

int 
sys_wait(tid_t tid){
  return process_wait(tid);
}

bool
sys_create(const char *file, unsigned initial_size){
  if(!file){
    sys_exit(-1);
    return false;
  }
  return filesys_create(file, initial_size);
}

bool
sys_remove(const char *file){
  return filesys_remove(file);
}

int 
sys_open(const char *file){
  int ret=-1;

  if(!file){
    sys_exit(-1);
  }
  struct thread *cur = thread_current();
  struct file *file_d = filesys_open(file);

  if(!file_d) return -1;
  for (int i=3; i<128; i++){
    if (cur->file[i] ==NULL){
      if (strcmp(cur->name,file)==0)
        file_deny_write(file_d);
      cur->file[i] = file_d;
      ret =i;
      cur->fd=cur->fd+1;
      break;
    }
  }
  return ret;
}

int 
sys_filesize(int fd){
  struct thread *cur = thread_current();
  struct file *file = cur->file[fd];
  if(!file) return -1;

  return file_length(file);
}

int 
sys_read(int fd, void *buffer, unsigned size){
  char c;
  unsigned i;
  check_valid_address(buffer, 0);
  if(fd == 0){
    for(i = 0 ; i < size ; i++){
      c = input_getc();
      if(c == '\0')
        break;
      ((char*)buffer)[i] = c;
    }
    return i-1;
  }
  struct thread *cur = thread_current();
  struct file *file = cur->file[fd];

  return file_read(file, buffer, size);

}

int 
sys_write(int fd, void *buffer, unsigned size){
  check_valid_address(buffer,0);
  if(fd == 1){
    putbuf((const char *)buffer, size);
    return size;
  }
  struct thread *cur = thread_current();
  struct file *file_d = cur->file[fd];
  if (!file_d) 
     sys_exit(-1);
  if (file_d->deny_write)
     file_deny_write(cur->file[fd]);

  return file_write(file_d, buffer, size);
}

void 
sys_seek(int fd, unsigned position){
  struct thread *cur = thread_current();
  struct file *file = cur->file[fd];
  if(!file) return;
  return file_seek(file, position);
}

unsigned 
sys_tell(int fd){
  struct thread *cur = thread_current();
  struct file *file = cur->file[fd];
  if(!file) return -1;
  return file_tell(file);
}

void 
sys_close(int fd){
  struct thread *cur = thread_current();
  struct file *file = cur->file[fd];
  if(!file) return;
  file_close(file);
  cur->file[fd] = NULL;
}

void 
check_valid_address(void *esp, int args){
  if((unsigned)esp + 4*args >= 0xc0000000 || (unsigned)esp < 0x8048000)
    sys_exit(-1);
}

static void
syscall_handler (struct intr_frame *f) 
{
  int number = *(int *)(f->esp);
  int status, fd;
  tid_t tid;
  const char *file, *cmd_line;
  unsigned initial_size, size, position;
  void *buffer;


  switch(number){
    case SYS_HALT:
      check_valid_address(f->esp, 0);
      sys_halt();
      break;
    case SYS_EXIT:
      check_valid_address(f->esp, 1);
      status = *(int *)(f->esp+4);
      sys_exit(status);
      break;
    case SYS_EXEC:
      check_valid_address(f->esp, 1);
      cmd_line = *(const char **)(f->esp+4);
      f->eax = sys_exec(cmd_line);
      break;
    case SYS_WAIT:
      check_valid_address(f->esp, 1);
      tid = *(int *)(f->esp+4);
      f->eax = sys_wait(tid);
      break;
    case SYS_CREATE:
      check_valid_address(f->esp, 2);
      file = *(const char **)(f->esp+4);
      initial_size = *(int *)(f->esp+8);
      f->eax = sys_create(file, initial_size);
      break;
    case SYS_REMOVE:
      check_valid_address(f->esp, 1);
      file = *(const char **)(f->esp+4);
      f->eax = sys_remove(file);
      break;
    case SYS_OPEN:
      check_valid_address(f->esp, 1);
      file = *(const char **)(f->esp+4);
      f->eax = sys_open(file);
      break;
    case SYS_FILESIZE:
      check_valid_address(f->esp, 1);
      fd = *(int *)(f->esp+4);
      f->eax = sys_filesize(fd);
      break;
    case SYS_READ:
      check_valid_address(f->esp, 3);
      fd = *(int *)(f->esp+4);
      buffer = *(void **)(f->esp+8);
      size = *(unsigned *)(f->esp+12);
      f->eax = sys_read(fd, buffer, size);
      break;
    case SYS_WRITE:
      check_valid_address(f->esp, 3);
      fd = *(int *)(f->esp+4);
      buffer = *(void **)(f->esp+8);
      size = *(unsigned *)(f->esp+12);
      f->eax = sys_write(fd, buffer, size);
      break;
    case SYS_SEEK:
      check_valid_address(f->esp, 2);
      fd = *(int *)(f->esp+4);
      position = *(unsigned *)(f->esp+8);
      sys_seek(fd, position);
      break;
    case SYS_TELL:
      check_valid_address(f->esp, 1);
      fd = *(int *)(f->esp+4);
      f->eax = sys_tell(fd);
      break;
    case SYS_CLOSE:
      check_valid_address(f->esp, 1);
      fd = *(int *)(f->esp+4);
      sys_close(fd);
      break;
    default:
      printf("error: wrong system call %d\n", number);
      thread_exit();
  }
}
