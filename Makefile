PROJECT := pma
TMP?=/tmp
CC?=gcc

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

LTOFLAGS := -flto -fno-fat-lto-objects -fuse-linker-plugin
OPTFLAGS := -O3 -fomit-frame-pointer -fstrict-aliasing -march=native -mtune=native -msse4.2
DEVFLAGS := -Wno-unused-parameter -Wno-unused-variable
EXTRA_WARNINGS := -Wextra -Wshadow -Wuninitialized -Wno-missing-field-initializers
CFLAGS?=-std=c99 -Wall $(OPTFLAGS) $(EXTRA_WARNINGS) -fstack-protector -Wno-error -fvisibility=hidden -D_GNU_SOURCE

MODULE_SRCS := $(wildcard e*.c)
MODULE_OBJS := $(MODULE_SRCS:.c=.o)
MODULE_NAMES := $(MODULE_SRCS:.c=)
TEST_SRCS := pma_test.c
TEST_EXES := $(TEST_SRCS:.c=)
TEST_MODULES := $(patsubst e%,%, $(MODULE_NAMES))

BACKUP_FILENAME:=$(TMP)/$(PROJECT)-backup-`date +"%Y-%m-%d"`.tar.xz
BACKUP_DIR=/mnt/media2015/backup/

ifdef PROFILEGEN
	CFLAGS+=-fprofile-generate
	NODEBUG=y
endif

ifdef PROFILEUSE
	CFLAGS+=-fprofile-use
	NODEBUG=y
endif

ifdef LTO
	CFLAGS+=${LTOFLAGS}
else
	CFLAGS+=-g
endif

ifndef NOVALGRIND
	CFLAGS+=-DUSE_VALGRIND -I$$HOME/local/include
endif

ifndef NODEBUG
	CFLAGS+=-DDEBUG $(DEVFLAGS)
endif

ifdef GCOV
	CFLAGS+=-fprofile-arcs -ftest-coverage
endif

ifdef MEMCHECK
	TEST_PREFIX:=valgrind --tool=memcheck --leak-check=full --track-origins=yes
endif

.PHONY: clean coverage strip test

all: pma_test

opt: clean
	@echo -e ${YELLOW}Building with profile generation...${NC}
	@LTO=1 PROFILEGEN=on make test
	@sha256sum pma_test
	@echo -e ${YELLOW}Removing old binaries${NC}
	@rm pma_test pma.o
	@echo -e ${YELLOW}Recompiling using profile data...${NC}
	@LTO=1 PROFILEUSE=on make pma_test
	@sha256sum pma_test

test: pma_test
	${TEST_PREFIX} ./pma_test
	@dd ibs=1 skip=16 if=test-p0000.bin status=none | sha256sum
	@dd ibs=1 skip=16 if=test-p0001.bin status=none | sha256sum

pma.o: pma.c pma.h

pma_test: pma_test.c pma.o
	$(CC) $(CFLAGS) $< -o $@ $(filter %.o, $^)

perf-cpu: pma_test
	perf stat -d ./pma_test

perf-tlb: pma_test
	perf stat -e dTLB-loads,dTLB-load-misses,dTLB-prefetch-misses ./pma_test

perf-llc: pma_test
	perf stat -e LLC-loads,LLC-load-misses,LLC-stores,LLC-prefetches ./pma_test

backup: clean
	@cd .. && tar -cJ --exclude=.git -f ${BACKUP_FILENAME} $(notdir $(CURDIR))
	@if [ $$? -eq 0 ]; then \
		mv ${BACKUP_FILENAME} ${BACKUP_DIR}; \
		echo "Backup ${BACKUP_FILENAME} written to ${BACKUP_DIR}"; \
	fi

strip:
	strip $(TEST_EXES)

clean:
	rm -f $(TEST_EXES) $(MODULE_OBJS) *.o vgcore* core core.* *.gcno *.gcna *.gcda *.c.gcov perf.data*

