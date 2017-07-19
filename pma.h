#pragma once
/*
	Page-based Block Allocator
	(C)2016, 2017 Eddy L O Jansson (@el0j)

	A simple region-based allocator.

	Design goals:
		Fast for small sub-allocations.
		Fast to free everything.
		Support many different types of underlying memory (malloc, mmap, shm)
		Handle alignment for you.
		Applications can use page ptr + alignment + offsets to reduce pointer waste.

	TODO:
		* Add macro/function to go to/from 'compressed address' based on page ptr + policy (alignment) + raw ptr
		* Allow nesting (a pma allocator on top of a pma_allocator with a different configuration)
		* Add valgrind macros if needed (check!)
		* Add attributes to functions, such as 'pure'

*/
#include <stdint.h>

#define IS_POW2(a) (a && !((a) & ((a)-1)))
#define UNUSED(x) UNUSED_ ## x  __attribute__((unused))

#define MALLOC_ADAPTER(fun, name) \
	static void *name(size_t size, void *UNUSED(data)) { return fun(size); }
#define CALLOC_ADAPTER(fun, name) \
	static void *name(size_t size, void *UNUSED(data)) { return fun(1, size); }
#define FREE_ADAPTER(fun, name) \
	static void name(void *ptr, void *UNUSED(data)) { fun(ptr); }

struct pma_page;

struct pma_policy {
	uint32_t region_size;
	uint32_t alignment_sub1;
	// uint32_t aux_size; /* XXX: size of auxillary base allocator in-page data */
	void* cb_data;
	void* (*malloc)(size_t size, void *cb_data);
	void  (*free)(void *ptr, void *cb_data);
};

int pma_init_policy(struct pma_policy *pol, uint32_t region_size, uint8_t pow2_alignment);
void pma_free(const struct pma_policy *pol, struct pma_page *p);

size_t pma_page_avail(const struct pma_policy *pol, struct pma_page *p);
size_t pma_max_allocation_size(const struct pma_policy *pol) __attribute__((pure));

struct pma_page *pma_new_page(const struct pma_policy *pol);
void *pma_alloc(const struct pma_policy *pol, struct pma_page **p, uint32_t size) __attribute__((malloc));
void *pma_alloc_onpage(const struct pma_policy *r, struct pma_page *p, uint32_t size) __attribute__((malloc));

void pma_debug_dump(const struct pma_policy *pol, struct pma_page *p, const char *basename);
