#include <iostream>
#include "SPiCall/SPiCall.h"

int main()
{
    SPiCall::init();
    SPiCall::syscall::nt_syscall("NtTerminateProcess", ~0, 0);
    return 0;
}
