#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

//#include <valgrind/valgrind.h>

#include "pma.h"

// #define ALIGN_ADDR(addr,align) (((addr)+(align-1)) & ~(align-1))
#define ALIGN_ADDR_PRESUB(addr,align) (((addr)+(align)) & ~((uintptr_t)align)) /* align is pow2-1 */
// #define ALIGN_ADDR_PRESUB_OFFSET(addr, align, k) ((addr)+(((uintptr_t)(k) - (addr)) & (uintptr_t)(align)))

CALLOC_ADAPTER(calloc, calloc_wrapped);
// MALLOC_ADAPTER(malloc, malloc_wrapped);
FREE_ADAPTER(free, free_wrapped);

struct pma_page {
	struct pma_page* next;
	uint32_t offset;
	// uint8_t aux[];
} __attribute__((packed));

int pma_init_policy(struct pma_policy *pol, uint32_t region_size, uint8_t pow2_alignment) {
	pol->region_size = region_size;
	pol->alignment = pow2_alignment;
	pol->alignment_mask = (1L << pow2_alignment) - 1;
	pol->malloc = calloc_wrapped;
	pol->free = free_wrapped;
	pol->cb_data = NULL;
	return 0;
}

void pma_free(const struct pma_policy *pol, struct pma_page *p) {
	while (p) {
		struct pma_page *next = p->next;
#ifdef DEBUG
		printf("Freeing %d page (%d used/%d free) @ %p (.next=%p)\n", pol->region_size, p->offset, pol->region_size - p->offset, p, next);
#endif
		pol->free(p, pol->cb_data);
		p = next;
	}
}

inline size_t pma_page_avail(const struct pma_policy *pol, struct pma_page *p) {
	return pol->region_size - p->offset;
}

inline size_t pma_page_header_size(const struct pma_policy *pol) {
	return sizeof(struct pma_page); // + pol->aux_size;
}

inline size_t pma_page_max_objects(const struct pma_policy *pol, size_t size) {
	size_t objs_size = ALIGN_ADDR_PRESUB(size, pol->alignment_mask);
	size_t objs = pma_max_allocation_size(pol) / objs_size;
	return objs;
}

inline size_t pma_max_allocation_size(const struct pma_policy *pol) {
	return pol->region_size - ALIGN_ADDR_PRESUB(pma_page_header_size(pol), pol->alignment_mask);
}

uint32_t pma_page_encode_offset(const struct pma_policy *pol, const struct pma_page *page, void *ptr) {
	uintptr_t diff = (uintptr_t)ptr - (uintptr_t)page - ALIGN_ADDR_PRESUB(pma_page_header_size(pol), pol->alignment_mask);
	return diff >> pol->alignment;
}

void *pma_page_decode_offset(const struct pma_policy *pol, const struct pma_page *page, uint32_t offset) {
	uintptr_t ptr = (uintptr_t)page + ALIGN_ADDR_PRESUB(pma_page_header_size(pol), pol->alignment_mask);
	return (void*)(ptr + ((uintptr_t)offset << pol->alignment));
}

struct pma_page *pma_new_page(const struct pma_policy *pol) {
	assert(pol != NULL);
	struct pma_page* np = pol->malloc(pol->region_size, pol->cb_data);
	if (np) {
#ifdef DEBUG
		printf("Allocated new %d byte page @ %p\n", pol->region_size, np);
#endif
		np->next = NULL;
		np->offset = ALIGN_ADDR_PRESUB(pma_page_header_size(pol), pol->alignment_mask);
	}
	return np;
}

void *pma_alloc(const struct pma_policy *pol, struct pma_page **p, uint32_t size) {
	// Make sure we can even fit size onto a new page if necessary.
	assert(pol != NULL);
	assert(size <= pma_max_allocation_size(pol));

	if (!*p || (pma_page_avail(pol, *p) < size && (p = &(*p)->next))) {
		*p = pma_new_page(pol);
		if (!*p)
			return NULL;
	}

	return pma_alloc_onpage(pol, *p, size);
}

void *pma_alloc_onpage(const struct pma_policy *pol, struct pma_page *p, uint32_t size) {
	assert(pol != NULL);
	assert(p != NULL);
	// Make sure we can fit size into this page.
	assert(pol->region_size - p->offset >= size);

#ifdef DEBUG
	printf("Sub-allocating %d bytes starting at offset %d of page @ %p\n", size, p->offset, p);
#endif
	void *retval = ((char*)p) + p->offset;
	p->offset = ALIGN_ADDR_PRESUB(p->offset + size, pol->alignment_mask);
	return retval;
}


void pma_debug_dump(const struct pma_policy *pol, struct pma_page *p, const char *basename) {
	char *fn;
	int page = 0;
	while (p) {
		asprintf(&fn, "%s-p%04d.bin", basename, page);
		FILE* f = fopen(fn, "w");
		if (f) {
			printf("Writing page @ %p to %s (%d bytes)\n", p, fn, p->offset);
			fwrite(p, p->offset, 1, f);
			fclose(f);
		}
		free(fn);
		++page;
		p = p->next;
	}
}
