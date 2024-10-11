#Building a BPF CO-RE Module

##References
 BCC Reference Guide:
- https://android.googlesource.com/platform/external/bcc/+/refs/heads/android10-c2f2-s1-release/docs/reference_guide.md
Libbpf Reference guide:
- https://github.com/libbpf/libbpf

- https://www.kernel.org/doc/html/latest/bpf/btf.html


## Preferred naming

So as to prevent confusion, name bpf clang modules corename.bpf.c

##Kernel BPF CO-RE Module

To generate a vmlinux.h file for CO-RE, run
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c >> vmlinux.h
```
DOC reference: https://nakryiko.com/posts/bpf-portability-and-co-re/

Add the git libbpf repo in your source as a submodule.
```
git submodule add https://github.com/libbpf/libbpf/ libbpf
```


Generate the BPF file.
```
clang -g -target bpf -c bpf_play.c  -o bpf_play.o

OR optimized

clang -O2 -target bpf -c bpf_play.c -o bpf_play.o
```

Load the BPF module into the kernel

```
sudo bpftool prog load bpf_play.o /sys/fs/bpf/bpf_play
```