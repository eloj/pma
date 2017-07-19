#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <valgrind/valgrind.h>

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
	pol->alignment_sub1 = (1L << pow2_alignment) - 1;
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
#ifdef __VALGRIND_MAJOR__
		// printf("FREE pool @ %p, mem @ %p\n", p,  p + ALIGN_ADDR_PRESUB(sizeof(struct pma_page), pol->alignment_sub1));
		// VALGRIND_MEMPOOL_FREE(p, p + ALIGN_ADDR_PRESUB(sizeof(struct pma_page), pol->alignment_sub1));
		// VALGRIND_DESTROY_MEMPOOL(p);
#endif
		p = next;
	}

}

inline size_t pma_page_avail(const struct pma_policy *pol, struct pma_page *p) {
	return pol->region_size - p->offset;
}

inline size_t pma_max_allocation_size(const struct pma_policy *pol) {
	return pol->region_size - ALIGN_ADDR_PRESUB(sizeof(struct pma_page), pol->alignment_sub1);
}

struct pma_page *pma_new_page(const struct pma_policy *pol) {
	struct pma_page* np = pol->malloc(pol->region_size, pol->cb_data);
	if (np) {
#ifdef DEBUG
		printf("Allocated new %d page @ %p\n", pol->region_size, np);
#endif
		np->next = NULL;
		np->offset = ALIGN_ADDR_PRESUB(sizeof(struct pma_page), pol->alignment_sub1);
	}
	return np;
}

void *pma_alloc(const struct pma_policy *pol, struct pma_page **p, uint32_t size) {
	// Make sure we can even fit size onto a new page if necessary.
	assert(size <= pma_max_allocation_size(pol));

	if (!*p || (pma_page_avail(pol, *p) < size && (p = &(*p)->next))) {
		*p = pma_new_page(pol);
	}
#if 0
	if (!*p) {
		*p = pma_new_page(pol);
	} else if (pma_page_avail(pol, *p) < size) {
		(*p)->next = pma_new_page(pol);
		*p = (*p)->next;
	}
#endif

	return pma_alloc_onpage(pol, *p, size);
}

void *pma_alloc_onpage(const struct pma_policy *pol, struct pma_page *p, uint32_t size) {
	// Make sure we can fit size into this page.
	assert(pol->region_size - p->offset >= size);

#ifdef DEBUG
	printf("Sub-allocating %d bytes starting at offset %d of page @ %p\n", size, p->offset, p);
#endif
	void *retval = ((char*)p) + p->offset;
	p->offset = ALIGN_ADDR_PRESUB(p->offset + size, pol->alignment_sub1);
#ifdef __VALGRIND_MAJOR__
	// VALGRIND_MALLOCLIKE_BLOCK(retval, size, 0, 0);
	// VALGRIND_MEMPOOL_ALLOC(p, retval, size);
#endif
	return retval;
}


void pma_debug_dump(const struct pma_policy *pol, struct pma_page *p, const char *basename) {
	char *fn;
	int page = 0;
	while (p) {
		asprintf(&fn, "%s-p%04d.bin", basename, page);
		FILE* f = fopen(fn, "w");
		if (f) {
			printf("Writing page @ %p to %s\n", p, fn);
			fwrite(p, pol->region_size, 1, f);
			fclose(f);
		}
		free(fn);
		++page;
		p = p->next;
	}
}
