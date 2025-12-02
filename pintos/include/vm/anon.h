#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"

#define INVALID_SLOT SIZE_MAX
#define SWAP_EMPTY ((size_t)-1)

struct page;
enum vm_type;

struct anon_page {
    size_t swap_slot;
};

void vm_anon_init (void);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);
void anon_page_destroy(struct anon_page *anon_page);

#endif
