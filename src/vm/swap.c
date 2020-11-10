#include "vm/swap.h"
#include "devices/block.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "frame.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

struct bitmap *swap_table;
struct block *swap_disk;
struct lock swap_lock;

void
swap_table_init(void){
    swap_table = bitmap_create(SWAP_DISK_SIZE);
    lock_init(&swap_lock);
}

void
swap_disk_init(void){
    swap_disk = block_get_role(BLOCK_SWAP);
}

bool 
load_from_swap(struct spte *spte){
    uint8_t *kpage = frame_alloc(PAL_USER, spte);
    if(!install_page_from_process(spte->upage, kpage, spte->writable)){
        printf("fail\n");
        destroy_frame_table(kpage);
        return false;
    }

    ASSERT(kpage);
    swap_in(spte, kpage);
    spte->state = MEMORY;
    spte->kpage=kpage;
    ASSERT(kpage);
    return true;
}

size_t
swap_out(struct fte *victim){
    lock_acquire(&swap_lock);
    size_t free_index = bitmap_scan_and_flip(swap_table, 0, 8, false);
    if(free_index == BITMAP_ERROR) ASSERT("No free index in swap disk");
    //printf("spte is 0x%x\n",victim->spte);
    //printf("file is 0x%x, buffer is 0x%x\n",victim->spte->file,victim->frame);
    if(victim->spte->file == 0xcccccccc) {
    print_hash();
    print_frame_list();
    }
    if (victim->spte->file)
        file_write_at(victim->spte->file, victim->frame, PGSIZE, victim->spte->offset);
    for(int i = 0 ; i < 8 ; i++)
        block_write(swap_disk, free_index + i, (uint8_t *)victim->frame + i * BLOCK_SECTOR_SIZE);

    lock_release(&swap_lock);
    
    return free_index;
}

void 
swap_in(struct spte* spte, void *frame_addr){

    lock_acquire(&swap_lock);
    if(bitmap_test(swap_table, spte->swap_location) == false)
        ASSERT("Trying to swap in a free block");
    
    bitmap_flip(swap_table, spte->swap_location);

    if (spte->file)
        file_read_at(spte->file, frame_addr, PGSIZE, spte->offset);

    for(int i = 0 ; i < 8 ; i++){
        block_read(swap_disk, spte->swap_location + i , (uint8_t *)frame_addr + i * BLOCK_SECTOR_SIZE);
    }
    bitmap_set_multiple(swap_table, spte->swap_location, 8, false);
    lock_release(&swap_lock);
}

void
swap_table_destroy(void){
    bitmap_destroy(swap_table);
}

void
swap_remove (size_t swap_location)
{
  lock_acquire (&swap_lock);
  bitmap_set (swap_table, swap_location, true);
  lock_release (&swap_lock);
}