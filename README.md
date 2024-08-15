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
sudo ./test/lyncean_test
```
### How To Use




