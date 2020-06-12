# SPiCall
Yet another windows syscall library

## Advantages
* Compatible with LLVM & MSVC
* Get ntdll without NtCreateFile or read the memory of loaded ntdll.dll to avoid hooks
* No string literals after compile (LLVM Ox)
* Easy to use
* No macros

## Usage
```C++
#include "SPiCall/SPiCall.h"

    SPiCall::init();
    // Easy to use: Invoke syscall with its name
    SPiCall::syscall::nt_syscall("NtTerminateProcess", ~0, 0);
```

## IDA decompile result
```C++
    SPiCall::init();
    // Safe: No string literals after compile
    v0 = SPiCall::syscall::get_syscall_no(0x1F2F8E87u);
    syscall_stub(v0, 2i64, -1i64, 0i64);
```

## System Hooked?
```C++
    if(!SPiCall::syscall::get_syscall_no("NtQueryVirtualMemory"))
    {
        // fail...
    }
```

## License
MIT License