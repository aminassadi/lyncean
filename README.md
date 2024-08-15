# Lyncean
Lyncean is a userspace utility tailored for diagnostics, debugging, and providing instructions, accessible via a classic command-line interface on Linux platforms. Unlike traditional tools such as strace, Lyncean stands out by utilizing eBPF.
Lyncean is currently under development; the list of available system calls can be found at "url://...". Additional system calls will be added soon, and contributions from the community are warmly welcomed.

### How To Build
## 1. Install Dependencies
For dependencies, it varies from distribution to distribution.
On Ubuntu, you may run make install or
```sh
sudo apt-get install -y --no-install-recommends \
        libelf1 libelf-dev zlib1g-dev \
        make cmake clang llvm

to install dependencies.
```
## 2. Clone And Build
clone:
```sh
git clone https://github.com/aminassadi/lyncean.git --recursive
```
update submodules:
```sh
git submodule update --init --recursive
```
build:
```sh
cd lyncean
mkdir build
cd build
cmake ..
make
cd test
sudo ./lyncean_test 
```
### How To Use
Lyncean allows tracing either by attaching to a specific process ID or executing a command directly. Moreover, it can trace child processes initiated by the traced process, especially when the -f or --follow-forks flag is utilized.
```sh
ubuntu@ubuntu-virtual-machine:~/repos/lyncean/build/src$ sudo ./lyncean -p 16934 -f
read(0, "l", 1) = 1
write(2, "l", 1) = 1
read(0, "s", 1) = 1
write(2, "s", 1) = 1
read(0, "\r", 1) = 1
write(2, "\n", 1) = 1
write(2, "\e[?2004l\r", 9) = 9
clone(..., flags=18874385, ...) = 33758
close(3) = 0
close(4) = 0
[pid=33758] close(4) = 0
[pid=33758] read(3, "", 1) = 0
[pid=33758] close(3) = 0
[pid=33758] openat(-100, /etc/ld.so.cache, 524288, 0) = 3
[pid=33758] close(3) = 0
[pid=33758] openat(-100, /lib/x86_64-linux-gnu/libselinux.so.1, 524288, 0) = 3
[pid=33758] read(3, "ELF>"..., 832) = 832
[pid=33758] close(3) = 0
[pid=33758] openat(-100, /lib/x86_64-linux-gnu/libc.so.6, 524288, 0) = 3
[pid=33758] read(3, "ELF>P�"..., 832) = 832
[pid=33758] close(3) = 0
[pid=33758] openat(-100, /lib/x86_64-linux-gnu/libpcre2-8.so.0, 524288, 0) = 3
[pid=33758] read(3, "ELF>"..., 832) = 832
[pid=33758] close(3) = 0
[pid=33758] openat(-100, /proc/filesystems, 524288, 0) = 3
[pid=33758] read(3, "nodev\tsysfs\nnodev\ttmpfs\nnodev\tbd"..., 1024) = 402
[pid=33758] read(3, "", 1024) = 0
[pid=33758] close(3) = 0
[pid=33758] openat(-100, /usr/lib/locale/locale-archive, 524288, 0) = 3
[pid=33758] close(3) = 0
[pid=33758] openat(-100, ., 591872, 0) = 3
[pid=33758] close(3) = 0
[pid=33758] write(1, "\e[0m\e[01;34mCMakeFiles\e[0m  cmak"..., 79) = 79
[pid=33758] close(1) = 0
[pid=33758] close(2) = 0
write(2, "\e[?2004h", 8) = 8
write(2, "\e]0;ubuntu@ubuntu-virtual-machin"..., 144) = 144
```






