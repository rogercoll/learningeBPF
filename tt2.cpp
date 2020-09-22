#include <iostream>
#include <bcc/BPF.h>
#include <string>
using namespace std;

struct data_t {
	pid_t pid;
	char comm[256];
};

std::string bpf_source = R"(

BPF_PERF_OUTPUT(event);

struct data_t {
	pid_t pid;
	char comm[256];

};
int mmap_fn(void* ctx)
{
	struct data_t data = {};
	data.pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(data.comm, 256);

	bpf_trace_printk("Hello world!\n");

	event.perf_submit(ctx, &data, sizeof(data));

	return 0;
}

)";

void handler(void* cookie, void* data, int sz) {
	auto d = static_cast<data_t*>(data);
	cout << "Pid: " << d->pid << " Comm: " << d->comm <<endl;
}

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

	
	auto res_open_perf = bpf.open_perf_buffer("event", handler);
	if (res_open_perf.code() != 0) {
		cerr << res_open_perf.msg() << endl;
	}

	while ( 0 <= bpf.poll_perf_buffer("event")) {

	}
	return 0;
}
