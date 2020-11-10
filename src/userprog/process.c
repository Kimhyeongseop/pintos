#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"
#include "vm/frame.h"

#define NUM_ARGS 128
#define FILE_LENGTH 16


static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  const char *c;
  char thread_name[FILE_LENGTH];
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  for(c = file_name ; *c != ' ' && *c != '\0' ; c++){
    thread_name[(unsigned)c - (unsigned)file_name] = *c;
  }
  thread_name[(unsigned)c - (unsigned)file_name] = '\0';

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page (fn_copy); 
  return tid;
}

void 
construct_arg_stack(char **args, int cnt, void **esp_ad){
  char *arg_ad[cnt];

  for(int i = cnt-1 ; i >= 0 ; i--){
    for(int j = strlen(args[i]) ; j >= 0 ; j--){
      (*esp_ad)--;
      **(char **)esp_ad = args[i][j];
    }
    arg_ad[i] = *esp_ad;
  }

  while((unsigned)(*esp_ad)%4 != 0)
    (*esp_ad)--;

  (*esp_ad) -= 4;

  for(int i = cnt-1 ; i >= 0 ; i--){
    (*esp_ad)-=4;
    **(char ***)esp_ad = arg_ad[i];
  }

  (*esp_ad)-=4;
  **(unsigned **)esp_ad = *(unsigned *)esp_ad+4;
  (*esp_ad)-=4;
  **(int **)esp_ad = cnt;
  (*esp_ad)-=4;
  **(int **)esp_ad = 0;
  
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  char *args[NUM_ARGS];
  char *save_ptr, *token;
  int cnt = 0;
  struct intr_frame if_;
  bool success;

  token = strtok_r(file_name, " ", &save_ptr);
  while(token != NULL){
    args[cnt] = token;
    cnt++;
    token = strtok_r(NULL, " ", &save_ptr);
  }

  init_spt(&thread_current()->hash);
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);


  if(success){
    construct_arg_stack(args, cnt, &if_.esp);
    thread_current()->load = true;
    //hex_dump(if_.esp , if_.esp , PHYS_BASE - (unsigned)if_.esp , true);
  }
  sema_up(&thread_current()->load_sema);

  /* If load failed, quit. */
  //palloc_free_page (file_name);

  if (!success){
    palloc_free_page(file_name);
    list_remove (&thread_current()->child_elem);
    thread_current()->load = false;
    thread_exit();
  }



  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

struct thread *
find_child(tid_t tid){
  struct thread *cur = thread_current();
  struct thread *child_thread = NULL;
  if(list_empty(&cur->child_list)){
    return NULL;
  }

  for(struct list_elem *child = list_begin(&cur->child_list) ;
    child != list_end(&cur->child_list) ;
    child = list_next(child)){
      struct thread *thr = list_entry(child, struct thread, child_elem);
      if(tid == thr->tid){
        child_thread = thr;
        break;
      }
    }
  return child_thread;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  struct thread* child = find_child(child_tid);
  int exit_status;

  if(!child){
    return -1;
  }

  sema_down(&child->exit_sema);

  list_remove(&child->child_elem);
  exit_status = child->exit_status;

  palloc_free_page(child);

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;

  for(int i = 2 ; i < cur->fd ; i++){
    file_close(cur->file[i]);
  }

  //print_hash();

//  for(unsigned i = 0 ; i < cur->hash.bucket_cnt ; i++){
//     struct list *bucket = &cur->hash.buckets[i];

//     int size = list_size(bucket);
//     //printf("bucket size %d\n",size);    
//     // for(struct list_elem *temp = list_begin(bucket) ;
//     //     temp != list_end(bucket) ;
//     //     temp = list_next(temp)){
//     //       struct hash_elem *elem  = list_elem_to_hash_elem(temp);
//     //       struct spte *spte = hash_entry(elem, struct spte, hash_elem);

//     //       if(spte == 0xcccccccc){
//     //         printf("cc in bucket %d, 0x%x!!\n",i,bucket);
//     //         continue;
//     //       } 

//     //       //if(!delete_spte(&cur->hash, spte)) printf("delete failed\n");
//     //     }
//   }
  destroy_spte(&cur->hash);
  
  //shutdown_power_off();

  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
    file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  //file_close (file);
  if(file)
    file_allow_write(file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  //printf("read_bytes of %s is %d, ofs is %d\n",thread_current()->name,read_bytes,ofs);
  //printf("file is 0x%x, upage is 0x%x\n", file,upage);
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      //printf("upage loading : 0x%x\n",upage);
      //printf("read_bytes is %d, zero_bytes is %d\n",read_bytes, zero_bytes);

      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct spte *spte = malloc(sizeof(struct spte));
      if(!spte) return false;

      spte->file = file;
      spte->upage = upage;
      spte->read_bytes = page_read_bytes;
      spte->zero_bytes = page_zero_bytes;
      spte->offset = ofs;
      spte->state = EXEC_FILE;
      spte->writable = writable;
      spte->pagedir = thread_current()->pagedir;

      create_spte(&thread_current()->hash, spte);

      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;

      //printf("file is 0x%x, file_inode length is %d\n",file, inode_length(file_get_inode(spte->file)));
      //print_hash();

    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  void *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
  struct spte *spte = malloc(sizeof(struct spte));

  uint8_t *kpage = frame_alloc(PAL_USER, spte);
  //printf("kpage for this process is 0x%x\n",kpage);
  if (kpage != NULL)
    {
      if (!install_page (upage, kpage, true))
        { 
          palloc_free_page (kpage);
          free (spte);
          return false;
        }
      *esp = PHYS_BASE;
      memset (spte, 0, sizeof (struct spte));
      spte->upage=upage;
      spte->writable=1;
      spte->state=MEMORY;
      spte->kpage=kpage;
      spte->pagedir = thread_current()->pagedir;
      //printf("spte is 0x%x, upage is 0x%x\n", spte, spte->upage);
      create_spte(&thread_current ()->hash, spte);
      thread_current()->fault_esp = PHYS_BASE;
    }
    return true;
  // uint8_t *kpage;
  // bool success = false;
  
  // kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  // if (kpage != NULL) 
  //   {
  //     success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
  //     if (success)
  //       *esp = PHYS_BASE;
  //     else
  //       palloc_free_page (kpage);
  //   }
  // return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

bool 
install_page_from_process(void *upage, void *kpage, bool writable){
  return install_page(upage, kpage, writable);
}