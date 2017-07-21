#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>

// for mmap/munmap
#include <sys/mman.h>
// for shm
#include <sys/ipc.h>
#include <sys/shm.h>

#include "pma.h"

/*
void* shm_alloc(size_t size, void *cb_data) {
	return NULL;
}

void shm_free(void *ptr, void *cb_data) {
}*/

// TODO: want to create a root pma based on mmaped hugepages, and then
// add a 4k allocator on top of that.

// TODO: demonstrate basic vbyte compression of addresses (1-2 bytes)

struct mmap_policy_data {
	size_t alloc_len;
	int flags;
};

__attribute__((malloc)) void* mmap_alloc(size_t size, void *cb_data) {
	struct mmap_policy_data *data = cb_data;

	void *mem = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | data->flags, -1, 0);
	return mem != MAP_FAILED ? mem : NULL;
}

void mmap_free(void *ptr, void *cb_data) {
	struct mmap_policy_data *data = cb_data;
	munmap(ptr, data->alloc_len);
}

int main(int argc, char *argv[]) {
	size_t page_size = sysconf(_SC_PAGE_SIZE);
	int alignment = argc > 1 ? atoi(argv[1]) : 4;

	printf("arg1 alignment=%d\n", alignment);

	// page_size = 2048*1024;
	printf("HW page size=%zu\n", page_size);

	struct pma_policy pol;
	if (pma_init_policy(&pol, page_size, alignment) != 0) {
		return 1;
	}

#if 0
	struct mmap_policy_data mmap_alloc_cbdata = {
		page_size,
		MAP_NORESERVE // | MAP_HUGETLB // | MAP_HUGE_2MB
	};

	pol.malloc = mmap_alloc;
	pol.free = mmap_free;
	pol.cb_data = &mmap_alloc_cbdata;
#endif

	struct pma_page *mem = pma_new_page(&pol);
	struct pma_page *root = mem;

	printf("First page at %p\n", root);
	printf("Page header is %zu bytes, %zu bytes available (%zu bytes slack). Max allocation size is %zu bytes.\n",
		pma_page_header_size(&pol),
		pma_page_avail(&pol, mem),
		pol.region_size - pma_page_avail(&pol, mem) - pma_page_header_size(&pol),
		pma_max_allocation_size(&pol)
	);

#define alloc_test(pol, page, len, c) { \
	void *opage = *page; \
	char *a__ = pma_alloc((pol), (page), (len)); \
	memset((a__), (c), (len)); \
}

	printf("MAX 1 byte objs = %zu\n", pma_page_max_objects(&pol, 1));
	printf("MAX 8 byte objs = %zu\n", pma_page_max_objects(&pol, 8));
	printf("MAX 16 byte objs = %zu\n", pma_page_max_objects(&pol, 16));
	printf("MAX 64 byte objs = %zu\n", pma_page_max_objects(&pol, 64));
	printf("MAX 128 byte objs = %zu\n", pma_page_max_objects(&pol, 128));
	printf("MAX %zu byte objs = %zu\n", pma_max_allocation_size(&pol), pma_page_max_objects(&pol, pma_max_allocation_size(&pol)));
	printf("MAX %zu byte objs = %zu\n", pma_max_allocation_size(&pol) + 1, pma_page_max_objects(&pol, pma_max_allocation_size(&pol) + 1));

	int idx = 0;
	uint16_t arr[128];

	char *a = pma_alloc(&pol, &mem, 51);
	*a = 'A';
	arr[idx++] = pma_page_encode_offset(&pol, mem, a);
	a = pma_alloc(&pol, &mem, 123);
	*a = 'B';
	arr[idx++] = pma_page_encode_offset(&pol, mem, a);
	a = pma_alloc(&pol, &mem, 1);
	*a = 'C';
	arr[idx++] = pma_page_encode_offset(&pol, mem, a);

	for (int i=0 ; i < idx ; ++i) {
		printf("%d @[%06d] = '%s'\n", i, arr[i], (char*)pma_page_decode_offset(&pol, mem, arr[i]));
	}

#if 0
	alloc_test(&pol, &mem, 64, 'a');
	alloc_test(&pol, &mem, 32, 'b');
	alloc_test(&pol, &mem, 15, 'c');
	alloc_test(&pol, &mem, 7, 'd');
	alloc_test(&pol, &mem, 1, '1');
	alloc_test(&pol, &mem, 2, '2');
	alloc_test(&pol, &mem, 3, '3');
	alloc_test(&pol, &mem, 4, '4');
	alloc_test(&pol, &mem, pma_max_allocation_size(&pol), 'z');

	pma_debug_dump(&pol, root, "test");
#endif

#if 0
	printf("Press enter to free.");
	char *line = NULL;
	size_t len = 0;
	getline(&line, &len, stdin);
	free(line);
#endif

	pma_free(&pol, root);

	return 0;
}
