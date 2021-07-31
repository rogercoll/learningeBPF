#include <iostream>
#include <bcc/BPF.h>
#include <string>
using namespace std;
std::string bpf_source = R"(

int mmap_fn(void* ctx)
{
	bpf_trace_printk("Hello world!\n");
	return 0;
}

)";

int main(void) {
	ebpf::BPF bpf;
	bpf.init(bpf_source);

	auto syscall = bpf.get_syscall_fnname("mmap");
	cout << "the syscall we are looking for is called " <<syscall<< endl;
	
	auto rc = bpf.attach_kprobe(syscall, "mmap_fn");
	if (rc.code() != 0) {
		cerr << rc.msg() << endl;
		return 1;
	}

	sleep(10);
	return 0;
}
