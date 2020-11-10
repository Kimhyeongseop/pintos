#ifndef VM_SWAP_H
#define VM_SWAP_H
#define SWAP_DISK_SIZE 1 << 21

#include <bitmap.h>
#include "devices/ide.h"
#include "page.h"
#include "frame.h"
#include "threads/synch.h"

void swap_table_init(void);
void swap_disk_init(void);
bool load_from_swap(struct spte *spte);
size_t swap_out(struct fte *fte);
void swap_in(struct spte *spte, void *frame_addr);
struct spte *swap_update(struct spte *spte);
void swap_table_destroy(void);
void swap_remove (size_t swap_location);



#endif