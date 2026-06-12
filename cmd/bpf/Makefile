# kernel module Makefile for building eBPF objects
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86
BPF_CFLAGS += -Iheaders
BPF_CFLAGS += -Wall -Werror
BPF_CFLAGS += -mlittle-endian

# Individual source files (each compiles to its own .bpf.o)
SRCS := $(wildcard probes/**/*.bpf.c)
OBJS := $(SRCS:.bpf.c=.bpf.o)

# Combined objects (multi-file compilation, maps are shared)
LSM_COMBINED := probes/lsm/lsm_combined.bpf.o
DECEPTION_COMBINED := probes/lsm/deception_combined.bpf.o

.PHONY: all clean combined

all: $(OBJS)

# Individual compilation rule
%.bpf.o: %.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

# Combined targets -- compile map-sharing files together into one .o
#
# lsm_hooks + deception share the 'rb' ringbuf and 'taint_map' hash.
# When compiled individually and loaded together via cilium/ebpf,
# the Go loader deduplicates maps with the same name in SEC(".maps").
# The combined target below provides an alternative that avoids any
# map duplication concerns at the cost of a single larger object.
combined: all $(LSM_COMBINED)

$(LSM_COMBINED): probes/lsm/lsm_hooks.bpf.c probes/lsm/deception.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c probes/lsm/lsm_hooks.bpf.c -o probes/lsm/lsm_hooks.bpf.o
	$(CLANG) $(BPF_CFLAGS) -c probes/lsm/deception.bpf.c -o probes/lsm/deception.bpf.o
	$(LLVM_STRIP) -g probes/lsm/lsm_hooks.bpf.o
	$(LLVM_STRIP) -g probes/lsm/deception.bpf.o

clean:
	rm -f probes/**/*.bpf.o probes/**/*.ll probes/**/*.bpf.combined.o

# Print all targets for debugging
list:
	@echo "Individual objects:"
	@for o in $(OBJS); do echo "  $$o"; done
	@echo ""
	@echo "Combined targets:"
	@echo "  $(LSM_COMBINED)"
