#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
void construct_arg_stack(char **args, int cnt, void **esp_ad);
struct thread *find_child(tid_t tid);
int process_wait (tid_t tid);
void process_exit (void);
void process_activate (void);
bool install_page_from_process (void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
