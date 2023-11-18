#include "vm.hpp"

void VirtualMachine ()  {
    bool isVM = VM::detect();

	if (isVM) {
		std::cout << "Virtual Machine detected: " << VM::brand() << std::endl;
	}
}
