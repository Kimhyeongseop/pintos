#include "vm/frame.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "filesys/inode.h"
#include "userprog/process.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

struct lock frame_table_lock;
struct list frame_table;

void
frame_table_init(void){
  list_init(&frame_table);
  lock_init(&frame_table_lock);
  printf("frame_table initialized with 0x%x\n",&frame_table);
}

bool 
load_from_exec (struct spte *spte){

  ASSERT((spte->read_bytes + spte->zero_bytes)%PGSIZE == 0)
    
  off_t bytes_read;

  //if(spte == 0xc01549cc) print_hash();
  uint8_t *kpage = frame_alloc(PAL_USER, spte);
  // if(spte == 0xc01549cc) printf("kpage : 0x%x, offset is %d\n",kpage, spte->offset);
  // if(spte == 0xc01549cc) print_hash();

  
  //file_seek(spte->file,spte->offset);
  unsigned u = (unsigned)file_read_at(spte->file, kpage, spte->read_bytes, spte->offset);
  if(u != spte->read_bytes){
    printf("%d is not same with %d\n",u, spte->read_bytes);
    destroy_frame_table(kpage);
    return false;
  }
  memset(kpage + spte->read_bytes, 0, spte->zero_bytes);

  if(!install_page_from_process(spte->upage, kpage, spte->writable)){
    printf("fail\n");
    destroy_frame_table(kpage);
    return false;
  }
  spte->kpage=kpage;

  //printf("success\n");
  spte->state = MEMORY;
  ASSERT(kpage);
  return true;
  //spte->upage += PGSIZE;
}

bool
stack_growth(void *address){
  //printf("address is 0x%x\n",address);
  struct spte *spte=malloc(sizeof(struct spte));
  spte->upage = pg_round_down(address);
  spte->writable = 1;
  spte->state = MEMORY;
  spte->pagedir = thread_current()->pagedir;
  ASSERT(address);

  if(!create_spte(&thread_current()->hash, spte)){
    printf("create spte failed\n");
    return false;
  }
  void *kpage = frame_alloc(PAL_USER, spte);
  if(!kpage){
    printf("frame allocation failed\n");
    destroy_spte(spte);
    return false;
  }
  spte->kpage=kpage;
  //printf("spte is 0x%x, kpage is 0x%x, upage is 0x%x\n",spte,kpage, spte->upage);
  return install_page_from_process(spte->upage, kpage, true);
}

void * 
frame_alloc(enum palloc_flags flags, struct spte* new_spte){

  if((flags & PAL_USER) == 0)
    return NULL;

  void *frame = palloc_get_page(flags);
  if(!frame){
    struct fte *victim = find_victim();
    size_t swap_index = swap_out(victim);

    victim->spte->swap_location = swap_index;
    
    //if(new_spte == 0xc01549cc) printf("victim is 0x%x\n",victim->spte);
    update_spte(victim->spte);

    frame_table_update(victim, new_spte, thread_current());
    return victim->frame;
  }else{
    create_fte(frame, new_spte);
    return frame;
  }
}

struct fte *
find_victim(void){
  struct list_elem *evict_elem = list_pop_back(&frame_table);
  //printf("evict elem is 0x%x\n",evict_elem);
  list_push_front(&frame_table, evict_elem);
  return list_entry(evict_elem, struct fte, elem);
}


void 
print_frame_list(void){
  struct list_elem *begin_elem = list_begin(&frame_table);
  struct list_elem *end_elem = list_tail(&frame_table);

  int elem = 0;
  for (struct list_elem *temp=begin_elem; temp!=end_elem; temp=list_next(temp)){
      elem++;
      struct fte *fte= list_entry(temp, struct fte,elem);
      void * kpage=fte->frame;
      
      if(fte->spte == 0xc01055cc){
        //printf("frame is 0x%x, spte 0x%x, upage 0x%x\n",kpage, fte->spte, fte->spte->upage);
        uint32_t page = lookup_page_k(fte->spte->pagedir, fte->spte->upage);
        //printf("page is 0x%x\n",page);
      }
  }
  printf("total %d\n",elem);
}


void
create_fte(void *frame, struct spte *spte){
  struct fte *fte = malloc(sizeof(struct fte));

  fte->frame = frame;
  fte->spte = spte;
  fte->thread = thread_current();
  list_push_back(&frame_table, &fte->elem);
}


void 
frame_table_update(struct fte *fte, struct spte *new_spte, struct thread *cur){
  fte->spte = new_spte;
  fte->thread = cur;
}

void
destroy_frame_table(void *frame){
  palloc_free_page(frame);
}

void
frame_remove (void *kpage){
  lock_acquire (&frame_table_lock);
  struct list_elem *begin_elem = list_begin(&frame_table);
  struct list_elem *end_elem = list_tail(&frame_table);

  for (struct list_elem *temp=begin_elem; temp!=end_elem; temp=list_next(temp)){
      struct fte *fte= list_entry(temp, struct fte,elem);
      void * frame=fte->frame;
      if (frame==pg_round_down(kpage)){
        list_remove (&fte->elem);
        free (fte);
        break;
      }
  }

  lock_release (&frame_table_lock);
}