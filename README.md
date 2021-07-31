# Learing eBPF

## Prerequisits

In Debian systems we can easily install the needed libs with:

```
sudo apt install libelf-dev libbpfcc-dev bpfcc-tools clang
```

## Usage

To generate and attach the BPF probes to the kernel we just need to compile and run the desired program:

```
make APP=file_name_without_cpp
sudo ./file_name_without_cpp
```

## Kprobes

- [Hello clone syscall](./hello_clone.cpp): Insert a hello world message for every clone syscall.
- [mmap syscall](./mmap1.cpp): Insert a hello world message for every mmap syscall.
