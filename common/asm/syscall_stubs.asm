; common/asm/syscall_stubs.asm
section .data
    ; These will be filled by our C++ Hook Detector
    global wNtAllocateVirtualMemorySSN
    wNtAllocateVirtualMemorySSN dd 0
    
    global wNtWriteVirtualMemorySSN
    wNtWriteVirtualMemorySSN dd 0

section .text
    global SyscallNtAllocateVirtualMemory
    global SyscallNtWriteVirtualMemory

SyscallNtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, [rel wNtAllocateVirtualMemorySSN]
    syscall
    ret

SyscallNtWriteVirtualMemory:
    mov r10, rcx
    mov eax, [rel wNtWriteVirtualMemorySSN]
    syscall
    ret
