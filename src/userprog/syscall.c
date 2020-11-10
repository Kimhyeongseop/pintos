#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <hash.h>
#include <syscall-nr.h>
#include <devices/shutdown.h>
#include <filesys/filesys.h>
#include <filesys/file.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "process.h"
#include "filesys/off_t.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/exception.h"


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
void check_valid_buffer(void* buffer, unsigned size, void *esp);
void check_valid_str(void* buffer);

struct lock read_write;
struct lock create_open;

void
syscall_init (void) 
{
  lock_init(&read_write);
  lock_init(&create_open);
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
  lock_acquire(&create_open);
  tid_t child_pid = process_execute(cmd_line);
  struct thread *child = find_child(child_pid);
  
  sema_down(&child->load_sema);
  if(child->load == false){
    lock_release(&create_open);
    return -1;
  }

  if(!child){
    lock_release(&create_open);
     return -1;
   }
  lock_release(&create_open);

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
  lock_acquire(&create_open);
  bool success=filesys_create(file, initial_size);
  lock_release(&create_open);
  return success;
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
  lock_acquire(&create_open);
  struct thread *cur = thread_current();
  struct file *file_d = filesys_open(file);
    if(!file_d) {
      lock_release(&create_open);
      return -1;
    }
  for (int i=3; i<128; i++){
    if (cur->file[i] == NULL){
      if (strcmp(cur->name,file)==0)
        file_deny_write(file_d);
      cur->file[i] = file_d;
      ret =i;
      cur->fd=cur->fd+1;
      break;
    }
  }
  lock_release(&create_open);
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
  lock_acquire(&read_write);
  if(fd == 0){
    for(i = 0 ; i < size ; i++){
      c = input_getc();
      if(c == '\0')
        break;
      ((char*)buffer)[i] = c;
    }
    lock_release(&read_write);  
    return i-1;
  }
  struct thread *cur = thread_current();
  struct file *file = cur->file[fd];
  lock_release(&read_write);
  return file_read(file, buffer, size);
}

int 
sys_write(int fd, void *buffer, unsigned size){
  check_valid_string(buffer);
  //printf("content of buffer is %s\n",buffer);
  if(fd == 1){
    putbuf((const char *)buffer, size);
    return size;
  }  
  lock_acquire(&read_write);
  struct thread *cur = thread_current();
  struct file *file_d = cur->file[fd];
  if (!file_d) {
    lock_release(&read_write);  
     sys_exit(-1);
  }
  if (file_get_deny_write(file_d)){
    //file_deny_write(file_d);
    lock_release(&read_write);  
     return 0;
  }
  int bytes_write = file_write(file_d, buffer, size);
  lock_release(&read_write);  
  //file_allow_write(file_d);
  return bytes_write;
}

void 
sys_seek(int fd, unsigned position){
  struct thread *cur = thread_current();
  struct file *file = cur->file[fd];
  if(!file) return;
  file_seek(file, position);
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
  //file_allow_write(file);
  file_close(file);
  cur->file[fd] = NULL;
}

void
check_valid_address(void *esp, int args){
  if((unsigned)esp + 4*args >= 0xc0000000 || (unsigned)esp < 0x8048000)
     sys_exit(-1);
  
}

void
check_valid_buffer(void* buffer, unsigned size, void *esp){
  //printf("buffer is 0x%x\n", buffer);
  //print_hash();
  struct spte *spte = get_spte(buffer);
  // if (strlen(buffer) +size > PGSIZE){
  //   sys_exit(-1);
  // }
  
  if (!spte){
    // if(buffer> USER_VADDR_BOTTOM && is_user_vaddr(buffer) &&(buffer >= esp - STACK_HEURISTIC)){
    // void* position= pg_round_down(buffer);
    //  struct spte *buf_spte;
    //  do{
    //   stack_growth(position);
    //   buf_spte = get_spte(position);
    //   position+=PGSIZE;
    //   }while(buffer+size > buf_spte->upage);
    // }
    // else{
      sys_exit(-1);
    }
    //printf("here\n");
    //print_hash();

  else if (!spte->writable){
    sys_exit(-1);
  }
}

void
check_valid_string(void *str)
{
  if((unsigned)str >= 0xc0000000 || (unsigned)str < 0x8048000)
     sys_exit(-1);
  // struct spte *spte = get_spte(str);
  //  if(!spte){
  //    printf("hi\n");
  //     sys_exit(-1);}
}

static void
syscall_handler (struct intr_frame *f) 
{
  check_valid_address(f->esp, 0);
  thread_current()->fault_esp = f->esp;
  int number = *(int *)(f->esp);
  int status, fd;
  tid_t tid;
  const char *file, *cmd_line;
  unsigned initial_size, size, position;
  void *buffer;

  //printf("syscall with number %d\n",number);

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
      check_valid_address(buffer,0);
      //check_valid_buffer(buffer, size, f->esp);
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
      sys_exit(-1);
      //printf("error: wrong system call %d\n", number);
      //thread_exit();
  }
}
