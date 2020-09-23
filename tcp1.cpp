#include <iostream>
#include <bcc/BPF.h>
#include <string>
#include <algorithm>
using namespace std;

struct stack_info_t {
	pid_t pid;
	char name[16];
	int user_stack;
	int kernel_stack;
};

std::string bpf_source = R"(
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

struct stack_info_t {
	pid_t pid;
	char name[16];
	int user_stack;
	int kernel_stack;
};

BPF_STACK_TRACE(stack_traces, 16384);
BPF_HASH(counts, struct stack_info_t, uint64_t);

int on_tcp_send(struct pt_regs *ctx)
{
	struct stack_info_t data = {};
	data.pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(&data.name, sizeof(data.name));

	data.kernel_stack = stack_traces.get_stackid(ctx, 0);
	data.user_stack = stack_traces.get_stackid(ctx, BPF_F_USER_STACK);

	u64 zero = 0, *val;
	val = counts.lookup_or_try_init(&data, &zero);
	if (val) {
		(*val)++;
	}
	bpf_trace_printk("Hello world!\n");
	return 0;
}

)";

int main(void) {
	ebpf::BPF bpf;
	bpf.init(bpf_source);

	auto syscall = bpf.get_syscall_fnname("tcp_sendmsg");
	cout << "the syscall we are looking for is called " <<syscall<< endl;
	
	auto rc = bpf.attach_kprobe("tcp_sendmsg" , "on_tcp_send");
	if (rc.code() != 0) {
		cerr << rc.msg() << endl;
		return 1;
	}

	sleep(10);

	auto detach_res = bpf.detach_kprobe("tcp_sendmsg");
	if (detach_res.code() != 0) {
		cerr << rc.msg() << endl;
		return 1;
	}

	

	auto table = bpf.get_hash_table<stack_info_t, uint64_t>("counts").get_table_offline();
	sort(table.begin(), table.end(),
		[](pair<stack_info_t, uint64_t> a,
		   pair<stack_info_t, uint64_t> b){return a.second < b.second;});
	auto stacks = bpf.get_stack_table("stack_traces");

	int lost_stacks = 0;
	for (auto it : table) {
		cout << "PID: " << it.first.pid << " (" << it.first.name << ") " << "made " << it.second << "TCP sends on the following stack: " << endl;
		
		if (it.first.kernel_stack >= 0) {
			cout << "  Kernel Stack:" <<endl;
			auto ksyms = stacks.get_stack_symbol(it.first.kernel_stack, -1);
			for (auto ksym : ksyms) {
				cout << "	" << ksym << endl;
			}
		} else if (it.first.kernel_stack != -EFAULT) {
			lost_stacks++;
			cout << "  [Lost Kernel Stack" << it.first.kernel_stack << "]" << endl;
		}

		if (it.first.user_stack >= 0) {
			cout << "  User Stack:" <<endl;
			auto usyms = stacks.get_stack_symbol(it.first.user_stack, it.first.pid);
			for (auto usym : usyms) {
				cout << "	" << usym << endl;
			}
		} else if (it.first.user_stack != -EFAULT) {
			lost_stacks++;
			cout << "  [Lost User Stack" << it.first.kernel_stack << "]" << endl;
		}
	
	}	

	return 0;
}
