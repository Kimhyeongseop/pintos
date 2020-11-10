#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "filesys/file.h"
#include <hash.h>

enum status{
    SWAP_DISK, MEMORY, EXEC_FILE
};

struct spte {
    struct hash_elem hash_elem;

    enum status state;      // SWAP_DISK, EXEC_FILE, MEMORY
    void *upage;            // Virtual address of an user page
    void *kpage;

    // for lazy loading
    struct file *file;
    size_t offset;          // file start point
    size_t read_bytes;      // bytes that has to be read
    size_t zero_bytes;      // bytes that has to be filled with 0

    // for swap
    uint32_t pagedir;
    size_t swap_location;
    bool writable;
};

void init_spt(struct hash *hash);
struct spte *get_spte(void *fault_address);
bool create_spte(struct hash *hash, struct spte *spte);
void update_spte(struct spte *spte);
//bool delete_spte(struct hash *hash, struct spte *spte);
void destroy_spte(struct hash *hash);
void delete_spte (struct hash_elem *elem, void *pt);

#endif