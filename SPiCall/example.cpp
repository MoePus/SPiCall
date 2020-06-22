#include <iostream>
#include "SPiCall/SPiCall.h"

int main()
{
    SPiCall::init();
#ifdef _MSC_VER
    const auto funcNameHash = SPiCall::syscall::fnv1a_32("NtTerminateProcess");
    SPiCall::syscall::nt_syscall(funcNameHash, ~0, 0);
#else
    SPiCall::syscall::nt_syscall("NtTerminateProcess", ~0, 0);
#endif
    return 0;
}
