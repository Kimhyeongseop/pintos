#include "vm/page.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <list.h>
#include <hash.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"
#include "vm/swap.h"

static unsigned
spt_hash_func(const struct hash_elem *elem, void *aux UNUSED){
    struct spte *spte = hash_entry(elem, struct spte, hash_elem);
    return hash_int((int)spte->upage);
}

static bool
spt_less_func(const struct hash_elem *a_elem, const struct hash_elem *b_elem, void *aux UNUSED){

    struct spte *a_spte = hash_entry(a_elem, struct spte, hash_elem);
    struct spte *b_spte = hash_entry(b_elem, struct spte, hash_elem);

    if(hash_int((int)b_spte) > hash_int((int)a_spte))
        return true;
    else 
        return false;

}

void 
init_spt(struct hash *hash){
    hash_init(hash, spt_hash_func, spt_less_func, hash);
}

struct spte*
get_spte(void *fault_address){
    void *page_num = pg_round_down(fault_address);
    //printf("pagenum is 0x%x\n",page_num);
    return hash_entry(find_spte(page_num), struct spte, hash_elem);
}


bool
create_spte(struct hash *hash, struct spte *spte){

    struct hash_elem *elem = hash_insert(hash, &spte->hash_elem);

    if(!elem)
        return true;
    else
        return false;

}


void 
update_spte(struct spte *spte){
    spte->state = SWAP_DISK;
    //if(spte == 0xc0177c0c) printf("upage is 0x%x\n",spte->upage);
    pagedir_clear_page(spte->pagedir, spte->upage);
}

// bool
// delete_spte(struct hash *hash, struct spte *spte){
//     //printf("try to free 0x%x\n",spte);
//     struct hash_elem *elem = hash_delete(hash, &spte->hash_elem);
//     if(!elem)
//         return false;
//     else{
//         //printf("state is %d\n", spte->state);
//         free(spte);
//         return true;
//     }
// }

void
destroy_spte(struct hash *hash){
    //print_hash();
    hash_destroy(hash, delete_spte);
}

void
delete_spte (struct hash_elem *elem, void *pt)
{
    struct spte *spte = hash_entry (elem, struct spte, hash_elem);
    void *kpage = spte->kpage;

    if (kpage != NULL)
        frame_remove (kpage);

    else if (spte->state == SWAP_DISK)
        swap_remove (spte->swap_location);

    if (pt != NULL)
        hash_delete ((struct hash*)pt, &spte->hash_elem);

    free (spte);
}