#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/palloc.h"
#include "swap.h"
#include "threads/thread.h"
#include <list.h>

struct fte{
    void *frame;
    struct spte *spte;
    struct thread *thread;
    struct list_elem elem;
};

void frame_table_init(void);
struct fte *find_victim(void);
void create_fte(void *frame, struct spte *spte);
void frame_table_update(struct fte *fte, struct spte *new_spte, struct thread *cur);
void destroy_frame_table(void *frame);
bool stack_growth(void *address);
void print_frame_list(void);

bool load_from_exec (struct spte *spte);
void * frame_alloc(enum palloc_flags PAL_USER,struct spte* spte);
void frame_remove (void *kpage);

#endif