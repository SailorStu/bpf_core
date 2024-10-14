
OUTPUT := bin
CLANG ?= clang
LIBBPF_SRC := $(abspath libbpf/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)

VMLINUX := vmlinux.h


TARGETS := $(addprefix $(OUTPUT)/,$(patsubst %.bpf.c,%.bpf.o,$(wildcard *.bpf.c)))

#
# Need target arch for using the correct bpf function parameters via ctx. 
#

BPF_CFLAGS := -g -O2 -target bpf -c -D__TARGET_ARCH_x86

.PHONY: all clean distclean

all: $(VMLINUX) $(LIBBPF_OBJ) $(TARGETS)
	$(Q)echo "Prebuild complete\n"

clean:
	$(Q)rm -rf $(OUTPUT)

distclean: clean
	$(Q)rm -f $(VMLINUX)

$(OUTPUT):
	$(Q)mkdir -p $@

$(VMLINUX): 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c >> $(VMLINUX)


# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install
	$(Q)printf "Built libbpf\n"
	$(Q)echo Targets are $(TARGETS)

# build our module

$(TARGETS): *.bpf.c $(VMLINUX) $(LIBBPF_OBJ)
	$(Q)$(CLANG) $(BPF_CFLAGS) -I. -I$(LIBBPF_SRC)/../usr/include -c $< -o $@