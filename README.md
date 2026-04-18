# Custom PE Manual Mapper & Direct Syscall Engine

A high-performance, modular Windows internal tool developed for research into EDR evasion and manual PE loading.

### Key Features
* **Manual Mapping:** Custom implementation of PE stretching, base relocation, and IAT resolution.
* **Direct Syscalls:** Implementation of Halo's Gate logic to dynamically discover SSNs and bypass User-Mode hooks.
* **Evasion:** Compile-time FNV-1a API hashing and PEB/EAT walking (no standard Windows APIs).
* **Architecture:** Modular C++ design with x64 ASM syscall stubs.

### Components
* `core/parser`: Custom PE parsing without standard headers.
* `techniques/evasion`: Dynamic hook detection and syscall restoration.
