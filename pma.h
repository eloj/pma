#pragma once
/*
	Page-based Block Allocator
	(C)2016, 2017 Eddy L O Jansson (@el0j)

	A simple region-based allocator.

	Design goals:
		Fast for small sub-allocations.
		Fast to free everything.
		Aid in writing cache friendly data-structures.
		Aid ptr waste reduction via indexed object encoding.
		Support many different types of underlying memory (malloc, mmap, shm)
		Handle alignment for you.

	TODO:
 		* mark/restore for temp work. (problematic when arenas linked)
		* Allow nesting (a pma allocator on top of a pma_allocator with a different configuration)
		* How to handle NULL in indexed encoding (pre-add 1 to offsets returned to free up 0, or just leave it to application)
		* Can VALGRIND client macros be moved into allocator cb's and still work well?
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

struct pma {
	const struct pma_policy *policy;
	struct pma_page *root;
	struct pma_page *curr;
};

enum pma_flags {
	PMA_ALLOC_INITIALIZED = 1
};

struct pma_policy {
	uint32_t region_size;
	uint16_t alignment;
	uint16_t alignment_mask;
	enum pma_flags flags;
	// uint32_t aux_size; /* XXX: size of auxillary base allocator in-page data */
	void* (*alloc)(size_t size, void *cb_data);
	void  (*free)(void *ptr, void *cb_data);
	void* cb_data;
};

int pma_init_policy(struct pma_policy *pol, uint32_t region_size, uint8_t pow2_alignment);
void pma_init(struct pma *pma, const struct pma_policy *pol);
void pma_free(struct pma *pma);

size_t pma_avail(const struct pma *pma);
size_t pma_page_header_size(const struct pma_policy *pol) __attribute__((pure));
size_t pma_page_max_objects(const struct pma_policy *pol, size_t size) __attribute__((pure));
size_t pma_max_allocation_size(const struct pma_policy *pol) __attribute__((pure));

uint32_t pma_page_encode_offset(const struct pma *pma, void *ptr);
void *pma_page_decode_offset(const struct pma *pma, uint32_t offset);

void *pma_alloc(struct pma *pma, size_t size) __attribute__((alloc_size(2)));
void *pma_push_string(struct pma *pma, const char *str, ssize_t len);
void *pma_push_struct(struct pma *pma, void *mem, size_t len);

void pma_debug_dump(const struct pma *pma, const char *basename);

