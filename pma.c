#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#ifdef DEBUG
// The Valgrind markup is not useful when allocations are backed by anything Valgrind already tracks,
// such as standard heap allocations, but should be used in other cases, such as when the backing is mmap'ed.
// If you're using both, know that standard heap allocations will be double-counted.
#ifdef USE_VALGRIND
#include "valgrind/memcheck.h"
#endif
#endif

#include "pma.h"

struct pma_page *pma_new_page(const struct pma_policy *pol);
void *pma_alloc_onpage(const struct pma_policy *r, struct pma_page *p, uint32_t size) __attribute__((malloc, alloc_size(3)));

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
}; // __attribute__((packed));

void pma_init(struct pma *pma, const struct pma_policy *pol) {
	pma->policy = pol;
	pma->root = NULL;
	pma->curr = NULL;
}

int pma_init_policy(struct pma_policy *pol, uint32_t region_size, uint8_t pow2_alignment) {
	pol->region_size = region_size;
	pol->alignment = pow2_alignment;
	pol->alignment_mask = (1L << pow2_alignment) - 1;
	pol->alloc = calloc_wrapped;
	pol->free = free_wrapped;
	pol->flags = PMA_ALLOC_INITIALIZED;
	pol->cb_data = NULL;
	return 0;
}

void pma_free(struct pma *pma) {
	if (!pma || !pma->root)
		return;

	struct pma_page *p = pma->root;

	// No free-function, then nothing to do.
	if (!pma->policy->free) {
#ifdef DEBUG
		printf("Requested freeing of page @ %p, but no pol->free defined.\n", p);
#endif
#ifdef __VALGRIND_MAJOR__
		VALGRIND_MEMPOOL_FREE(p, p);
		VALGRIND_DESTROY_MEMPOOL(p);
#endif
		return;
	}
	while (p) {
		struct pma_page *next = p->next;
#ifdef DEBUG
		printf("Freeing %d page (%d used/%d free) @ %p (.next=%p)\n", pma->policy->region_size, p->offset, pma->policy->region_size - p->offset, p, next);
#endif
		pma->policy->free(p, pma->policy->cb_data);
#ifdef __VALGRIND_MAJOR__
		VALGRIND_MEMPOOL_FREE(p, p);
		VALGRIND_DESTROY_MEMPOOL(p);
#endif
		p = next;
	}
}

inline size_t pma_avail(const struct pma *pma) {
	return pma->policy->region_size - pma->curr->offset;
}

inline size_t pma_page_header_size(const struct pma_policy *pol) {
	(void)pol;
	return sizeof(struct pma_page);
}

inline size_t pma_page_max_objects(const struct pma_policy *pol, size_t size) {
	size_t objs_size = ALIGN_ADDR_PRESUB(size, pol->alignment_mask);
	size_t objs = pma_max_allocation_size(pol) / objs_size;
	return objs;
}

inline size_t pma_max_allocation_size(const struct pma_policy *pol) {
	return pol->region_size - ALIGN_ADDR_PRESUB(pma_page_header_size(pol), pol->alignment_mask);
}

uint32_t pma_page_encode_offset(const struct pma *pma, void *ptr) {
	uintptr_t diff = (uintptr_t)ptr - (uintptr_t)pma->curr - ALIGN_ADDR_PRESUB(pma_page_header_size(pma->policy), pma->policy->alignment_mask);
	return diff >> pma->policy->alignment;
}

void *pma_page_decode_offset(const struct pma *pma, uint32_t offset) {
	uintptr_t ptr = (uintptr_t)pma->curr + ALIGN_ADDR_PRESUB(pma_page_header_size(pma->policy), pma->policy->alignment_mask);
	return (void*)(ptr + ((uintptr_t)offset << pma->policy->alignment));
}

struct pma_page *pma_new_page(const struct pma_policy *pol) {
	assert(pol != NULL);
	struct pma_page *np = pol->alloc(pol->region_size, pol->cb_data);
	if (np) {
#ifdef DEBUG
		printf("Allocated new %d byte page @ %p\n", pol->region_size, np);
#endif
		np->next = NULL;
		np->offset = ALIGN_ADDR_PRESUB(pma_page_header_size(pol), pol->alignment_mask);
#ifdef __VALGRIND_MAJOR__
		VALGRIND_CREATE_MEMPOOL_EXT(np, 0, pol->flags & PMA_ALLOC_INITIALIZED, VALGRIND_MEMPOOL_METAPOOL | VALGRIND_MEMPOOL_AUTO_FREE);
		VALGRIND_MEMPOOL_ALLOC(np, np, pol->region_size);
		VALGRIND_MAKE_MEM_NOACCESS(np, sizeof(struct pma_page));
		VALGRIND_MAKE_MEM_DEFINED(np, pma_page_header_size(pol));
#endif
	}
	return np;
}

void *pma_alloc_onpage(const struct pma_policy *pol, struct pma_page *p, uint32_t size) {
	assert(pol != NULL);
	assert(p != NULL);
	// Make sure we can fit size into this page.
	assert(pol->region_size - p->offset >= size);

	void *retval = NULL;
	if (pol->region_size - p->offset >= size) {
		#ifdef DEBUG
		// printf("Sub-allocating %d bytes starting at offset %d of page @ %p\n", size, p->offset, p);
		#endif
		retval = ((char*)p) + p->offset;
		p->offset = ALIGN_ADDR_PRESUB(p->offset + size, pol->alignment_mask);
#ifdef __VALGRIND_MAJOR__
		if (size)
			VALGRIND_MALLOCLIKE_BLOCK(retval, size, 0, pol->flags & PMA_ALLOC_INITIALIZED);
#endif
	}
	#ifdef DEBUG
	else {
		printf("Sub-allocation of %d bytes too large to fit a page.\n", size);
	}
	#endif
	return retval;
}

void *pma_alloc(struct pma *pma, size_t size) {
	assert(pma != NULL);
	assert(pma->policy != NULL);
	// Make sure we can even fit size onto a new page if necessary.
	assert(size <= pma_max_allocation_size(pma->policy));

	struct pma_page **p = &pma->root;

	if (!*p || (pma_avail(pma) < size && (p = &(pma->curr->next)))) {
		*p = pma_new_page(pma->policy);
		pma->curr = *p;
	}

	if (!pma->curr)
		return NULL;

	return pma_alloc_onpage(pma->policy, pma->curr, size);
}

void *pma_push_string(struct pma *pma, const char *str, ssize_t len) {
	char *s = NULL;
	size_t alen;

	if (len < 0)
		len = strlen(str);

	if (!__builtin_add_overflow(len, 1, &alen) && ((s = pma_alloc(pma, alen)) != NULL)) {
		memcpy(s, str, len);
		s[len] = 0;
	}

	return s;
}

void *pma_push_struct(struct pma *pma, void *mem, size_t len) {
	void *dest = pma_alloc(pma, len);
	memcpy(dest, mem, len);
	return dest;
}

void pma_debug_dump(const struct pma *pma, const char *basename) {
	char *fn;
	int pageno = 0;
	struct pma_page *p = pma->root;
	while (p) {
		asprintf(&fn, "%s-p%04d.bin", basename, pageno);
		FILE *f = fopen(fn, "w");
		if (f) {
			printf("Writing page @ %p to %s (%d bytes)\n", p, fn, p->offset);
			fwrite(p, p->offset, 1, f);
			fclose(f);
		}
		free(fn);
		++pageno;
		p = p->next;
	}
}
