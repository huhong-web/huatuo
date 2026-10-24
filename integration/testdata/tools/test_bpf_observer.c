// Copyright 2026 The HuaTuo Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
 * Record BPF object identities before the tracee can close their FDs. Seccomp
 * selects resource operations; ordinary syscalls run without ptrace stops.
 * All traced tasks are stopped during each selected syscall, because another
 * thread sharing the FD table could otherwise close/reuse its returned FD.
 * This tool supplies observations only. Shell owns the reclamation assertions.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/if_tun.h>
#include <linux/perf_event.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __aarch64__
#include <asm/ptrace.h>
#include <elf.h>
#endif

#if defined(__x86_64__)
#define OBSERVER_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define OBSERVER_ARCH AUDIT_ARCH_AARCH64
#else
#error "BPF observer supports native x86-64 and AArch64"
#endif

#define MAX_TASKS	    4096
#define MAX_CREATED_OBJECTS 65536
#define MAX_CONTROL_BYTES   65536

/* Stable UAPI values missing from older distro headers. */
enum {
	OBSERVER_MAP_TYPE_QUEUE = 22,
	OBSERVER_MAP_TYPE_STACK = 23,
	OBSERVER_MAP_UPDATE_BATCH = 26,
	OBSERVER_LINK_CREATE = 28,
	OBSERVER_LINK_UPDATE = 29,
	OBSERVER_LINK_GET_FD_BY_ID = 30,
	OBSERVER_SYSCALL_PROGRAM = 31,
	OBSERVER_PROG_BIND_MAP = 35,
	OBSERVER_IO_URING_SETUP_SYSCALL = 425,
	OBSERVER_IO_URING_ENTER_SYSCALL = 426,
	OBSERVER_OPEN_TREE_SYSCALL = 428,
	OBSERVER_MOVE_MOUNT_SYSCALL = 429,
	OBSERVER_FSMOUNT_SYSCALL = 432,
	OBSERVER_CLONE3_SYSCALL = 435,
	OBSERVER_MOUNT_SETATTR_SYSCALL = 442,
};

enum observation_event {
	RESOURCE_OPERATION,
	FOREIGN_SYSCALL_ABI,
	UNSUPPORTED_MUTATION,
	INSPECT_CLONE_FLAGS,
	INSPECT_SECCOMP_COMMAND,
	INSPECT_UNSHARE_FLAGS,
	INSPECT_SETNS_TYPE,
	SOCKET_OPTION_OPERATION,
	IOCTL_OPERATION,
	SENDMSG_OPERATION,
	SENDMMSG_OPERATION,
};

struct traced_task {
	pid_t pid;
	pid_t vfork_parent;
	bool stopped;
	bool operation;
	unsigned long operation_event;
	bool exiting;
	int signal;
};

struct object_id {
	const char *kind;
	unsigned int id;
	unsigned int program_type;
	unsigned int map_type;
};

struct operation {
	unsigned long args[6];
	unsigned int command;
	unsigned long attributes;
	unsigned long argument0;
	struct object_id pinned;
	struct object_id attachment_program;
	struct object_id mutation_target;
	char pin_path[PATH_MAX];
	bool pin_valid;
	bool mutation_valid;
};

static struct traced_task tasks[MAX_TASKS];
static struct object_id created_objects[MAX_CREATED_OBJECTS];
static size_t created_count;
static sigset_t observer_signals;
static const char *output_directory;
static FILE *inventory;
static pid_t root_pid;
static int root_status;
static bool complete;
static bool root_alive = true;
static bool term_forwarded;
static unsigned long record_count;

static void write_completion(void)
{
	char temporary[PATH_MAX];
	char destination[PATH_MAX];
	FILE *file;

	if (!output_directory)
		return;
	if (snprintf(temporary, sizeof(temporary), "%s/complete.tmp",
		     output_directory) >= (int)sizeof(temporary) ||
	    snprintf(destination, sizeof(destination), "%s/complete.json",
		     output_directory) >= (int)sizeof(destination))
		return;
	file = fopen(temporary, "we");
	if (!file)
		return;
	if (fprintf(file,
		    "{\"complete\":%s,\"root_pid\":%d,\"exit_status\":%d,"
		    "\"sigterm_forwarded\":%s,\"record_count\":%lu}\n",
		    complete ? "true" : "false", root_pid, root_status,
		    term_forwarded ? "true" : "false", record_count) < 0) {
		fclose(file);
		return;
	}
	if (fclose(file) == 0)
		rename(temporary, destination);
}

static void fail(const char *operation, pid_t pid)
{
	fprintf(stderr, "BPF observation failed: %s; tid=%d: %s\n", operation,
		pid, strerror(errno));
	if (root_pid > 0 && root_alive)
		kill(root_pid, SIGKILL);
	exit(1);
}

static void handle_signal(int signal)
{
	if (signal == SIGCHLD)
		return;
	if (signal != SIGTERM) {
		errno = EINTR;
		fail("observer interrupted", root_pid);
	}
	/* The parent never signals an identity it has already reaped. */
	if (!root_alive) {
		errno = ESRCH;
		fail("Agent exited before SIGTERM", root_pid);
	}
	if (kill(root_pid, SIGTERM) < 0)
		fail("forward SIGTERM to Agent", root_pid);
	term_forwarded = true;
}

static struct traced_task *task_for(pid_t pid)
{
	struct traced_task *empty = NULL;
	int i;

	for (i = 0; i < MAX_TASKS; i++) {
		if (tasks[i].pid == pid)
			return &tasks[i];
		if (!tasks[i].pid && !empty)
			empty = &tasks[i];
	}
	if (!empty) {
		errno = EOVERFLOW;
		fail("tracked task limit exceeded", pid);
	}
	empty->pid = pid;
	return empty;
}

static bool tasks_remaining(void)
{
	int i;

	for (i = 0; i < MAX_TASKS; i++)
		if (tasks[i].pid)
			return true;
	return false;
}

static void resume_task(struct traced_task *task, bool syscall_exit)
{
	if (ptrace(syscall_exit ? PTRACE_SYSCALL : PTRACE_CONT, task->pid, NULL,
		   (void *)(long)task->signal) < 0) {
		/* A SIGKILL death may already be queued for waitpid. */
		if (errno != ESRCH)
			fail("resume tracee", task->pid);
	}
	task->stopped = false;
	task->signal = 0;
}

static void read_registers(pid_t pid, struct operation *operation, long *result)
{
#ifdef __x86_64__
	struct user_regs_struct registers;

	if (ptrace(PTRACE_GETREGS, pid, NULL, &registers) < 0)
		fail("read syscall registers", pid);
	operation->args[0] = registers.rdi;
	operation->args[1] = registers.rsi;
	operation->args[2] = registers.rdx;
	operation->args[3] = registers.r10;
	operation->args[4] = registers.r8;
	operation->args[5] = registers.r9;
	*result = (long)registers.rax;
#else
	struct user_pt_regs registers;
	struct iovec buffer = {&registers, sizeof(registers)};

	if (ptrace(PTRACE_GETREGSET, pid, (void *)NT_PRSTATUS, &buffer) < 0)
		fail("read syscall registers", pid);
	memcpy(operation->args, registers.regs, sizeof(operation->args));
	*result = (long)registers.regs[0];
#endif
	operation->command = operation->args[0];
	operation->argument0 = operation->args[0];
	operation->attributes = operation->args[1];
}

static bool
read_memory(pid_t pid, unsigned long address, void *data, size_t size)
{
	struct iovec remote = {(void *)address, size};
	struct iovec local = {data, size};

	return process_vm_readv(pid, &local, 1, &remote, 1, 0) == (ssize_t)size;
}

static bool resource_event(pid_t pid, unsigned long event)
{
	struct operation operation = {0};
	uint64_t flags;
	long result;

	if (event == RESOURCE_OPERATION || event == SENDMSG_OPERATION ||
	    event == SENDMMSG_OPERATION)
		return true;
	read_registers(pid, &operation, &result);
	if (event == SOCKET_OPTION_OPERATION) {
		unsigned int level = operation.args[1];
		unsigned int option = operation.args[2];

		return (level == SOL_SOCKET &&
			(option == SO_ATTACH_BPF ||
			 option == SO_ATTACH_REUSEPORT_EBPF ||
			 option == SO_ATTACH_FILTER ||
			 option == SO_ATTACH_REUSEPORT_CBPF)) ||
		       ((level == IPPROTO_IP || level == IPPROTO_IPV6) &&
			option == 64);
	}
	if (event == IOCTL_OPERATION) {
		unsigned int request = operation.args[1];

		return request == PERF_EVENT_IOC_SET_BPF ||
		       request == PERF_EVENT_IOC_SET_OUTPUT ||
		       request == TUNSETSTEERINGEBPF ||
		       request == TUNSETFILTEREBPF ||
		       request == TUNATTACHFILTER;
	}
	if (event == INSPECT_CLONE_FLAGS &&
	    read_memory(pid, operation.argument0, &flags, sizeof(flags)) &&
	    !(flags & (CLONE_UNTRACED | CLONE_NEWNS | CLONE_NEWUSER)))
		return false;
	if (event == INSPECT_SECCOMP_COMMAND && operation.command >= 2)
		return false;
	if (event == INSPECT_UNSHARE_FLAGS &&
	    !(operation.argument0 & (CLONE_NEWNS | CLONE_NEWUSER)))
		return false;
	if (event == INSPECT_SETNS_TYPE && operation.attributes &&
	    !(operation.attributes & (CLONE_NEWNS | CLONE_NEWUSER)))
		return false;
	fprintf(stderr, "unsupported observation event %lu, argument0=%lu\n",
		event, operation.argument0);
	errno = ENOTSUP;
	fail("syscall would bypass BPF observation", pid);
	return false;
}

static struct traced_task *wait_event(bool *syscall_exit)
{
	struct traced_task *task;
	unsigned long message;
	unsigned int event;
	pid_t pid;
	int status;

	*syscall_exit = false;
	for (;;) {
		const struct timespec no_wait = {0};
		int signal;

		while ((signal = sigtimedwait(&observer_signals, NULL,
					      &no_wait)) > 0)
			handle_signal(signal);
		if (errno != EAGAIN)
			fail("read pending observer signals", root_pid);
		pid = waitpid(-1, &status, __WALL | WNOHANG);
		if (pid != 0)
			break;
		/* Signals stay blocked between waitpid and sigwaitinfo: an exit
		 * or shutdown request cannot be lost in that interval. */
		signal = sigwaitinfo(&observer_signals, NULL);
		if (signal < 0)
			fail("wait for tracee or shutdown signal", root_pid);
		handle_signal(signal);
	}
	if (pid < 0)
		fail("wait for tracee", root_pid);
	task = task_for(pid);
	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		if (pid == root_pid) {
			root_alive = false;
			root_status = WIFEXITED(status)
					      ? WEXITSTATUS(status)
					      : 128 + WTERMSIG(status);
		}
		memset(task, 0, sizeof(*task));
		return NULL;
	}
	if (!WIFSTOPPED(status)) {
		errno = EPROTO;
		fail("unexpected wait status", pid);
	}
	task->stopped = true;
	task->signal = 0;
	event = (unsigned int)status >> 16;
	switch (event) {
	case PTRACE_EVENT_FORK:
	case PTRACE_EVENT_VFORK:
	case PTRACE_EVENT_CLONE:
		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &message) < 0)
			fail("read descendant identity", pid);
		task_for((pid_t)message)->vfork_parent =
			event == PTRACE_EVENT_VFORK ? pid : 0;
		break;
	case PTRACE_EVENT_EXEC:
		task->vfork_parent = 0;
		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &message) < 0)
			fail("read exec identity", pid);
		if ((pid_t)message != pid) {
			struct traced_task *old = task_for((pid_t)message);

			memset(old, 0, sizeof(*old));
		}
		break;
	case PTRACE_EVENT_SECCOMP:
		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &message) < 0)
			fail("read seccomp event", pid);
		task->operation = resource_event(pid, message);
		task->operation_event = message;
		break;
	case PTRACE_EVENT_STOP:
		if (WSTOPSIG(status) != SIGTRAP) {
			errno = ENOTSUP;
			fail("unexpected process group-stop", pid);
		}
		break;
	case PTRACE_EVENT_EXIT:
		task->exiting = true;
		break;
	case 0:
		if (WSTOPSIG(status) == (SIGTRAP | 0x80))
			*syscall_exit = true;
		else
			task->signal = WSTOPSIG(status);
		break;
	default:
		errno = EPROTO;
		fail("unknown ptrace event", pid);
	}
	return task;
}

static void stop_other_tasks(void)
{
	struct traced_task *task;
	bool syscall_exit;
	bool running;
	int i;

	for (i = 0; i < MAX_TASKS; i++) {
		if (!tasks[i].pid || tasks[i].stopped)
			continue;
		if (ptrace(PTRACE_INTERRUPT, tasks[i].pid, NULL, NULL) < 0 &&
		    errno != ESRCH)
			fail("stop task sharing a possible FD table",
			     tasks[i].pid);
	}
	for (;;) {
		running = false;
		for (i = 0; i < MAX_TASKS; i++)
			if (tasks[i].pid && !tasks[i].stopped)
				running = true;
		if (!running)
			return;
		task = wait_event(&syscall_exit);

		/* A vfork parent cannot stop until its child has execed/exited.
		 */
		if (task && task->vfork_parent) {
			if (task->operation) {
				errno = ENOTSUP;
				fail("resource operation before vfork child "
				     "exec",
				     task->pid);
			}
			resume_task(task, false);
		}
		if (syscall_exit) {
			errno = EPROTO;
			fail("unmatched syscall exit while stopping tasks",
			     root_pid);
		}
	}
}

static bool read_object_id(pid_t pid, int fd, struct object_id *object)
{
	char path[64];
	char line[256];
	FILE *file;

	snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", pid, fd);
	file = fopen(path, "re");
	if (!file)
		return false;
	while (fgets(line, sizeof(line), file)) {
		unsigned int id;

		if (sscanf(line, "prog_type: %u", &id) == 1) {
			object->program_type = id;
		} else if (sscanf(line, "map_type: %u", &id) == 1) {
			object->map_type = id;
		} else if (sscanf(line, "link_id: %u", &id) == 1) {
			object->kind = "link";
			object->id = id;
		} else if (sscanf(line, "map_id: %u", &id) == 1) {
			object->kind = "map";
			object->id = id;
		} else if (!object->kind &&
			   sscanf(line, "prog_id: %u", &id) == 1) {
			object->kind = "prog";
			object->id = id;
		}
	}
	if (ferror(file)) {
		int error = errno ? errno : EIO;

		fclose(file);
		errno = error;
		return false;
	}
	if (fclose(file))
		return false;
	if (object->kind && object->id)
		return true;
	errno = ENODATA;
	return false;
}

static void capture_pin(pid_t pid, struct operation *operation)
{
	struct {
		uint64_t pathname;
		uint32_t fd;
		uint32_t flags;
	} attributes;
	size_t i;

	if (!read_memory(pid, operation->attributes, &attributes,
			 sizeof(attributes)) ||
	    !read_object_id(pid, (int)attributes.fd, &operation->pinned))
		return;
	for (i = 0; i < sizeof(operation->pin_path); i++) {
		if (!read_memory(pid, attributes.pathname + i,
				 &operation->pin_path[i], 1))
			return;
		if (!operation->pin_path[i]) {
			operation->pin_valid = operation->pin_path[0] != 0;
			return;
		}
	}
}

static void resolve_pin(pid_t pid, struct operation *operation)
{
	char tracee_path[PATH_MAX + 64];
	struct stat observer_mount;
	struct stat tracee_mount;
	char namespace_path[64];
	char resolved[PATH_MAX];

	snprintf(namespace_path, sizeof(namespace_path), "/proc/%d/ns/mnt",
		 pid);
	if (stat("/proc/self/ns/mnt", &observer_mount) ||
	    stat(namespace_path, &tracee_mount) ||
	    observer_mount.st_dev != tracee_mount.st_dev ||
	    observer_mount.st_ino != tracee_mount.st_ino) {
		errno = ENOTSUP;
		fail("cannot verify a pin in a different mount namespace", pid);
	}
	if (operation->pin_path[0] == '/')
		snprintf(tracee_path, sizeof(tracee_path), "/proc/%d/root%s",
			 pid, operation->pin_path);
	else
		snprintf(tracee_path, sizeof(tracee_path), "/proc/%d/cwd/%s",
			 pid, operation->pin_path);
	if (!realpath(tracee_path, resolved))
		fail("resolve successful BPF pin", pid);
	strcpy(operation->pin_path, resolved);
}

static void write_json_string(const char *value)
{
	const unsigned char *p = (const unsigned char *)value;

	fputc('"', inventory);
	for (; *p; p++) {
		if (*p == '"' || *p == '\\')
			fprintf(inventory, "\\%c", *p);
		else if (*p < 32)
			fprintf(inventory, "\\u%04x", *p);
		else
			fputc(*p, inventory);
	}
	fputc('"', inventory);
}

static void capture_related_program(pid_t pid, struct operation *operation)
{
	unsigned int fd;

	if (!read_memory(pid, operation->attributes + 8, &fd, sizeof(fd)))
		return;
	read_object_id(pid, (int)fd, &operation->attachment_program);
}

static bool object_was_created(const struct object_id *object)
{
	size_t i;

	for (i = 0; i < created_count; i++)
		if (created_objects[i].id == object->id &&
		    !strcmp(created_objects[i].kind, object->kind))
			return true;
	return false;
}

static bool map_holds_only_data(unsigned int type)
{
	switch (type) {
	case BPF_MAP_TYPE_HASH:
	case BPF_MAP_TYPE_ARRAY:
	case BPF_MAP_TYPE_PERCPU_HASH:
	case BPF_MAP_TYPE_PERCPU_ARRAY:
	case BPF_MAP_TYPE_STACK_TRACE:
	case BPF_MAP_TYPE_LRU_HASH:
	case BPF_MAP_TYPE_LRU_PERCPU_HASH:
	case BPF_MAP_TYPE_LPM_TRIE:
	case OBSERVER_MAP_TYPE_QUEUE:
	case OBSERVER_MAP_TYPE_STACK:
		return true;
	default:
		return false;
	}
}

static bool may_add_references(unsigned int command)
{
	return command == BPF_MAP_UPDATE_ELEM ||
	       command == OBSERVER_MAP_UPDATE_BATCH ||
	       command == OBSERVER_PROG_BIND_MAP;
}

static void inspect_reference_mutation(pid_t pid, struct operation *operation)
{
	struct object_id *target = &operation->mutation_target;
	unsigned long offset = 0;
	unsigned int fd;

	/* The batch UAPI places map_fd after four pointers and a count. */
	if (operation->command == OBSERVER_MAP_UPDATE_BATCH)
		offset = 4 * sizeof(uint64_t) + sizeof(uint32_t);
	if (!read_memory(pid, operation->attributes + offset, &fd,
			 sizeof(fd))) {
		errno = EPROTO;
		fail("cannot read BPF mutation target FD", pid);
	}
	if (!read_object_id(pid, (int)fd, target)) {
		/* Invalid FDs are used by capability probes and cannot mutate a
		 * container. Other inspection errors must stop before a batch
		 * can partially succeed and still return an error. */
		if (!target->id && (errno == ENOENT || errno == ENODATA))
			return;
		fail("cannot inspect BPF mutation target", pid);
	}
	operation->mutation_valid = true;
	if (object_was_created(target))
		return;
	if (operation->command != OBSERVER_PROG_BIND_MAP &&
	    !strcmp(target->kind, "map") &&
	    map_holds_only_data(target->map_type))
		return;
	/* Owned containers are checked by their lifetime. A borrowed container
	 * can outlive the Agent with new references, without a new ID or pin.
	 */
	fprintf(stderr,
		"unobservable BPF command=%u through borrowed %s id=%u "
		"map_type=%u\n",
		operation->command, target->kind, target->id, target->map_type);
	errno = ENOTSUP;
	fail("cannot track references added to a borrowed BPF object", pid);
}

static void
inspect_program_attachment(pid_t pid, int fd, struct operation *operation)
{
	struct object_id *program = &operation->mutation_target;

	if (!read_object_id(pid, fd, program)) {
		if (!program->id && (errno == ENOENT || errno == ENODATA))
			return;
		fail("inspect attachment program FD", pid);
	}
	if (strcmp(program->kind, "prog"))
		return;
	if (!object_was_created(program)) {
		fprintf(stderr,
			"attachment operation=%u references borrowed program "
			"id=%u\n",
			operation->command, program->id);
		errno = ENOTSUP;
		fail("cannot track attachment of borrowed BPF program", pid);
	}
	operation->mutation_valid = true;
}

static void inspect_socket_option(pid_t pid, struct operation *operation)
{
	unsigned int option = operation->args[2];
	int fd;

	operation->command = option;
	if ((unsigned int)operation->args[1] != SOL_SOCKET ||
	    (option != SO_ATTACH_BPF && option != SO_ATTACH_REUSEPORT_EBPF)) {
		errno = ENOTSUP;
		fail("opaque classic BPF or firewall attachment is unsupported",
		     pid);
	}
	if (operation->args[4] < sizeof(fd))
		return;
	if (!read_memory(pid, operation->args[3], &fd, sizeof(fd))) {
		errno = EPROTO;
		fail("read socket attachment program FD", pid);
	}
	inspect_program_attachment(pid, fd, operation);
}

static void inspect_attachment_ioctl(pid_t pid, struct operation *operation)
{
	unsigned int request = operation->args[1];
	int fd = operation->args[2];

	operation->command = request;
	if (request == TUNATTACHFILTER) {
		errno = ENOTSUP;
		fail("opaque classic BPF attachment is unsupported", pid);
	}
	if (request == PERF_EVENT_IOC_SET_OUTPUT) {
		if (fd != -1) {
			errno = ENOTSUP;
			fail("perf output redirection can retain unobserved "
			     "references",
			     pid);
		}
		operation->mutation_valid = true;
		return;
	}
	if (request == TUNSETSTEERINGEBPF || request == TUNSETFILTEREBPF) {
		if (!read_memory(pid, operation->args[2], &fd, sizeof(fd))) {
			errno = EPROTO;
			fail("read TUN/TAP attachment program FD", pid);
		}
		if (fd == -1) {
			operation->mutation_valid = true;
			return;
		}
	}
	inspect_program_attachment(pid, fd, operation);
}

static void inspect_control_messages(pid_t pid, const struct msghdr *message)
{
	unsigned long address = (unsigned long)message->msg_control;
	size_t remaining = message->msg_controllen;
	struct cmsghdr control;
	size_t step;

	if (remaining > MAX_CONTROL_BYTES) {
		errno = EOVERFLOW;
		fail("socket control message exceeds observation limit", pid);
	}
	while (remaining >= sizeof(control)) {
		if (!read_memory(pid, address, &control, sizeof(control))) {
			errno = EPROTO;
			fail("read socket control message", pid);
		}
		if (control.cmsg_len < sizeof(control) ||
		    control.cmsg_len > remaining)
			return;
		if (control.cmsg_level == SOL_SOCKET &&
		    control.cmsg_type == SCM_RIGHTS) {
			errno = ENOTSUP;
			fail("SCM_RIGHTS descriptor transfer is unsupported",
			     pid);
		}
		step = CMSG_ALIGN(control.cmsg_len);
		if (step > remaining)
			return;
		remaining -= step;
		address += step;
	}
}

static void require_nonblocking_send(pid_t pid, int fd, unsigned long flags)
{
	char path[64];
	char line[256];
	unsigned int file_flags = 0;
	FILE *file;

	if (flags & MSG_DONTWAIT)
		return;
	snprintf(path, sizeof(path), "/proc/%d/fdinfo/%d", pid, fd);
	file = fopen(path, "re");
	if (!file)
		fail("inspect send blocking mode", pid);
	while (fgets(line, sizeof(line), file))
		if (sscanf(line, "flags: %o", &file_flags) == 1)
			break;
	if (ferror(file)) {
		fclose(file);
		fail("read send blocking mode", pid);
	}
	if (fclose(file))
		fail("close send blocking-mode metadata", pid);
	if (!(file_flags & O_NONBLOCK)) {
		errno = ENOTSUP;
		fail("blocking sends cannot be serialized with the process "
		     "tree",
		     pid);
	}
}

/* Only sendmsg variants can export FDs. The barrier must cover kernel
 * consumption of control bytes; blocking variants could deadlock a stopped
 * peer, so this observer requires MSG_DONTWAIT or an O_NONBLOCK socket. */
static void
inspect_send(pid_t pid, unsigned long event, struct operation *operation)
{
	struct msghdr message;
	unsigned long flags;
	size_t count = 1;
	size_t i;

	if (event == SENDMMSG_OPERATION)
		count = operation->args[2];
	flags = operation->args[event == SENDMSG_OPERATION ? 2 : 3];
	if (count > 1024) {
		errno = EOVERFLOW;
		fail("send message count exceeds observation limit", pid);
	}
	require_nonblocking_send(pid, operation->args[0], flags);
	for (i = 0; i < count; i++) {
		if (!read_memory(pid,
				 operation->args[1] +
					 i * sizeof(struct mmsghdr),
				 &message, sizeof(message))) {
			errno = EPROTO;
			fail("read sendmsg header", pid);
		}
		inspect_control_messages(pid, &message);
	}
}

static int observer_bpf(unsigned int command, union bpf_attr *attributes)
{
	return syscall(SYS_bpf, command, attributes, sizeof(*attributes));
}

static void read_kernel_info(pid_t pid, int fd, void *info, size_t size)
{
	union bpf_attr attributes = {
		.info.bpf_fd = fd,
		.info.info_len = size,
		.info.info = (uint64_t)(uintptr_t)info,
	};

	if (observer_bpf(BPF_OBJ_GET_INFO_BY_FD, &attributes))
		fail("read BPF reference metadata", pid);
}

static void inspect_program_maps(pid_t pid, const struct object_id *program)
{
	union bpf_attr attributes = {.prog_id = program->id};
	struct bpf_prog_info info = {0};
	struct bpf_map_info map = {0};
	struct object_id object = {.kind = "map"};
	unsigned int *ids;
	unsigned int count;
	unsigned int i;
	int program_fd;
	int map_fd;

	program_fd = observer_bpf(BPF_PROG_GET_FD_BY_ID, &attributes);
	if (program_fd < 0)
		fail("inspect newly loaded program maps", pid);
	read_kernel_info(pid, program_fd, &info, sizeof(info));
	count = info.nr_map_ids;
	if (count > MAX_CREATED_OBJECTS) {
		errno = EOVERFLOW;
		fail("program map references exceed observation limit", pid);
	}
	if (!count) {
		close(program_fd);
		return;
	}
	ids = calloc(count, sizeof(*ids));
	if (!ids)
		fail("allocate program map identities", pid);
	memset(&info, 0, sizeof(info));
	info.nr_map_ids = count;
	info.map_ids = (uint64_t)(uintptr_t)ids;
	read_kernel_info(pid, program_fd, &info, sizeof(info));
	if (info.nr_map_ids > count) {
		errno = EOVERFLOW;
		fail("program map references changed during observation", pid);
	}
	for (i = 0; i < info.nr_map_ids; i++) {
		object.id = ids[i];
		if (object_was_created(&object))
			continue;
		memset(&attributes, 0, sizeof(attributes));
		attributes.map_id = object.id;
		map_fd = observer_bpf(BPF_MAP_GET_FD_BY_ID, &attributes);
		if (map_fd < 0)
			fail("inspect borrowed program map", pid);
		memset(&map, 0, sizeof(map));
		read_kernel_info(pid, map_fd, &map, sizeof(map));
		close(map_fd);
		if (!map_holds_only_data(map.type)) {
			fprintf(stderr,
				"program id=%u references borrowed map id=%u "
				"type=%u\n",
				program->id, object.id, map.type);
			errno = ENOTSUP;
			fail("program may mutate a borrowed reference "
			     "container",
			     pid);
		}
	}
	free(ids);
	close(program_fd);
}

static void
record_operation(pid_t pid, struct operation *operation, long result)
{
	struct object_id object = {0};
	struct stat pin;
	bool created;

	if (result < 0)
		return;
	if (operation->command == BPF_PROG_TEST_RUN) {
		if (!operation->mutation_valid) {
			errno = EPROTO;
			fail("cannot identify successful BPF test-run target",
			     pid);
		}
		return;
	}
	if (may_add_references(operation->command)) {
		if (!operation->mutation_valid) {
			errno = EPROTO;
			fail("cannot identify successful BPF mutation target",
			     pid);
		}
		return;
	}
	if (operation->command == BPF_OBJ_PIN) {
		if (!operation->pin_valid) {
			errno = ENOTSUP;
			fail("cannot identify successful pin", pid);
		}
		resolve_pin(pid, operation);
		if (stat(operation->pin_path, &pin))
			fail("identify successful BPF pin inode", pid);
		fprintf(inventory,
			"{\"kind\":\"%s\",\"id\":%u,\"pid\":%d,\"created\":"
			"false,\"pin\":",
			operation->pinned.kind, operation->pinned.id, pid);
		write_json_string(operation->pin_path);
		fprintf(inventory, ",\"pin_identity\":\"%ju:%ju\"}\n",
			(uintmax_t)pin.st_dev, (uintmax_t)pin.st_ino);
	} else {
		if (!read_object_id(pid, (int)result, &object)) {
			if (operation->command != BPF_RAW_TRACEPOINT_OPEN ||
			    errno != ENODATA) {
				errno = EPROTO;
				fail("cannot identify successful BPF FD", pid);
			}
		}
		if (operation->command == BPF_RAW_TRACEPOINT_OPEN &&
		    (!object.kind || strcmp(object.kind, "link"))) {
			if (!operation->attachment_program.id) {
				errno = EPROTO;
				fail("cannot identify legacy attachment "
				     "program",
				     pid);
			}
			fprintf(inventory,
				"{\"kind\":\"prog\",\"id\":%u,\"pid\":%d,"
				"\"created\":false,\"legacy_attachment\":true}"
				"\n",
				operation->attachment_program.id, pid);
			if (ferror(inventory) || fflush(inventory))
				fail("write legacy attachment identity", pid);
			record_count++;
			return;
		}
		if (object.program_type == OBSERVER_SYSCALL_PROGRAM) {
			errno = ENOTSUP;
			fail("syscall BPF programs can create unobserved "
			     "objects",
			     pid);
		}
		if (operation->command == BPF_PROG_LOAD)
			inspect_program_maps(pid, &object);
		created = operation->command == BPF_MAP_CREATE ||
			  operation->command == BPF_PROG_LOAD ||
			  operation->command == OBSERVER_LINK_CREATE ||
			  (operation->command == BPF_RAW_TRACEPOINT_OPEN &&
			   !strcmp(object.kind, "link"));
		if (created) {
			if (created_count == MAX_CREATED_OBJECTS) {
				errno = EOVERFLOW;
				fail("created BPF identity limit exceeded",
				     pid);
			}
			created_objects[created_count++] = object;
		}
		fprintf(inventory,
			"{\"kind\":\"%s\",\"id\":%u,\"pid\":%d,\"created\":%s}"
			"\n",
			object.kind, object.id, pid,
			created ? "true" : "false");
	}
	if (ferror(inventory) || fflush(inventory))
		fail("write BPF resource record", pid);
	record_count++;
}

static void inspect_bpf_operation(pid_t pid, struct operation *operation)
{
	if (may_add_references(operation->command))
		inspect_reference_mutation(pid, operation);
	if (operation->command == BPF_OBJ_PIN)
		capture_pin(pid, operation);
	if (operation->command == BPF_RAW_TRACEPOINT_OPEN)
		capture_related_program(pid, operation);
	if (operation->command == BPF_PROG_TEST_RUN) {
		struct object_id program = {0};
		unsigned int fd;

		if (!read_memory(pid, operation->attributes, &fd, sizeof(fd)))
			fail("inspect test-run program FD", pid);
		if (!read_object_id(pid, (int)fd, &program)) {
			if (!program.id &&
			    (errno == ENOENT || errno == ENODATA))
				return;
			fail("inspect test-run program identity", pid);
		}
		operation->mutation_valid = true;
		if (!object_was_created(&program) ||
		    program.program_type == OBSERVER_SYSCALL_PROGRAM) {
			errno = ENOTSUP;
			fail("test-run may execute unobserved kernel side "
			     "effects",
			     pid);
		}
	}
	if (operation->command == BPF_PROG_LOAD) {
		unsigned int type;

		if (read_memory(pid, operation->attributes, &type,
				sizeof(type)) &&
		    type == OBSERVER_SYSCALL_PROGRAM) {
			errno = ENOTSUP;
			fail("syscall BPF programs may execute unobserved "
			     "kernel side effects",
			     pid);
		}
	}
}

static void
inspect_operation(pid_t pid, unsigned long event, struct operation *operation)
{
	switch (event) {
	case RESOURCE_OPERATION:
		inspect_bpf_operation(pid, operation);
		break;
	case SOCKET_OPTION_OPERATION:
		inspect_socket_option(pid, operation);
		break;
	case IOCTL_OPERATION:
		inspect_attachment_ioctl(pid, operation);
		break;
	case SENDMSG_OPERATION:
	case SENDMMSG_OPERATION:
		inspect_send(pid, event, operation);
		break;
	default:
		break;
	}
}

static void complete_operation(pid_t pid, unsigned long event,
			       struct operation *operation, long result)
{
	if (result < 0)
		return;
	switch (event) {
	case RESOURCE_OPERATION:
		record_operation(pid, operation, result);
		break;
	case SOCKET_OPTION_OPERATION:
	case IOCTL_OPERATION:
		if (!operation->mutation_valid) {
			errno = EPROTO;
			fail("cannot identify successful BPF attachment", pid);
		}
		break;
	default:
		break;
	}
}

static void observe_operations(void)
{
	struct traced_task *task;
	struct traced_task *event;
	struct operation operation;
	struct operation returned;
	bool syscall_exit;
	long result;
	int i;

	stop_other_tasks();
	for (;;) {
		task = NULL;
		for (i = 0; i < MAX_TASKS; i++)
			if (tasks[i].pid && tasks[i].operation) {
				task = &tasks[i];
				break;
			}
		if (!task)
			break;
		memset(&operation, 0, sizeof(operation));
		read_registers(task->pid, &operation, &result);
		inspect_operation(task->pid, task->operation_event, &operation);
		resume_task(task, true);
		for (;;) {
			event = wait_event(&syscall_exit);
			if (!task->pid || task->exiting) {
				errno = EPROTO;
				fail("tracee exited during observed resource "
				     "operation",
				     root_pid);
			}
			if (event != task)
				continue;
			if (syscall_exit) {
				read_registers(task->pid, &returned, &result);
				complete_operation(task->pid,
						   task->operation_event,
						   &operation, result);
				task->operation = false;
				break;
			}
			resume_task(task, true);
		}
	}
	for (i = 0; i < MAX_TASKS; i++)
		if (tasks[i].pid && tasks[i].stopped)
			resume_task(&tasks[i], false);
}

#define TRACE_COMMAND(command)                                                 \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (command), 0, 1),                  \
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE)

#define REJECT_SYSCALL(number)                                                 \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1),                   \
		BPF_STMT(BPF_RET | BPF_K,                                      \
			 SECCOMP_RET_TRACE | UNSUPPORTED_MUTATION)

#define TRACE_SYSCALL(number, event)                                           \
	BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1),                   \
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE | (event))

static void install_filter(void)
{
	struct sock_filter instructions[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, OBSERVER_ARCH, 1, 0),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | FOREIGN_SYSCALL_ABI),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
#ifdef __x86_64__
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | FOREIGN_SYSCALL_ABI),
#endif
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K,
			 CLONE_UNTRACED | CLONE_NEWNS | CLONE_NEWUSER, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | UNSUPPORTED_MUTATION),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, OBSERVER_CLONE3_SYSCALL, 0,
			 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | INSPECT_CLONE_FLAGS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_seccomp, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | INSPECT_SECCOMP_COMMAND),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_prctl, 0, 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PR_SET_SECCOMP, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | UNSUPPORTED_MUTATION),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_unshare, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | INSPECT_UNSHARE_FLAGS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setns, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | INSPECT_SETNS_TYPE),
	/* Inode identity survives renames, but hard links can add a pin
	 * without BPF_OBJ_PIN. Mount changes can hide surviving pins. */
#ifdef SYS_link
		REJECT_SYSCALL(SYS_link),
#endif
		REJECT_SYSCALL(SYS_linkat),
		REJECT_SYSCALL(SYS_mount),
		REJECT_SYSCALL(SYS_umount2),
		REJECT_SYSCALL(SYS_pivot_root),
		/* Stable native syscall numbers, absent from older headers. */
		/* Async file operations would bypass the syscall filter too. */
		REJECT_SYSCALL(OBSERVER_IO_URING_SETUP_SYSCALL),
		REJECT_SYSCALL(OBSERVER_IO_URING_ENTER_SYSCALL),
		REJECT_SYSCALL(OBSERVER_OPEN_TREE_SYSCALL),
		REJECT_SYSCALL(OBSERVER_MOVE_MOUNT_SYSCALL),
		REJECT_SYSCALL(OBSERVER_FSMOUNT_SYSCALL),
		REJECT_SYSCALL(OBSERVER_MOUNT_SETATTR_SYSCALL),
		TRACE_SYSCALL(SYS_setsockopt, SOCKET_OPTION_OPERATION),
		TRACE_SYSCALL(SYS_ioctl, IOCTL_OPERATION),
		TRACE_SYSCALL(SYS_sendmsg, SENDMSG_OPERATION),
		TRACE_SYSCALL(SYS_sendmmsg, SENDMMSG_OPERATION),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_bpf, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, args[0])),
		TRACE_COMMAND(BPF_MAP_CREATE),
		TRACE_COMMAND(BPF_MAP_UPDATE_ELEM),
		TRACE_COMMAND(OBSERVER_MAP_UPDATE_BATCH),
		TRACE_COMMAND(OBSERVER_PROG_BIND_MAP),
		TRACE_COMMAND(BPF_PROG_LOAD),
		TRACE_COMMAND(BPF_PROG_TEST_RUN),
		TRACE_COMMAND(BPF_OBJ_PIN),
		TRACE_COMMAND(BPF_OBJ_GET),
		TRACE_COMMAND(BPF_PROG_GET_FD_BY_ID),
		TRACE_COMMAND(BPF_MAP_GET_FD_BY_ID),
		TRACE_COMMAND(BPF_RAW_TRACEPOINT_OPEN),
		TRACE_COMMAND(OBSERVER_LINK_CREATE),
		TRACE_COMMAND(OBSERVER_LINK_GET_FD_BY_ID),
		/* Unsupported persistent mutations must not pass unobserved. */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BPF_PROG_ATTACH, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | UNSUPPORTED_MUTATION),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, OBSERVER_LINK_UPDATE, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | UNSUPPORTED_MUTATION),
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 36, 0, 1),
		BPF_STMT(BPF_RET | BPF_K,
			 SECCOMP_RET_TRACE | UNSUPPORTED_MUTATION),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog filter = {
		.len = sizeof(instructions) / sizeof(instructions[0]),
		.filter = instructions,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filter) < 0)
		fail("install resource-operation filter", getpid());
}

/* Network configuration can add references without bpf(), through tc/XDP
 * netlink or firewall rules naming pinned programs. This tracer-only scenario
 * has no network-administration contract. Remove that capability permanently
 * instead of parsing every protocol and every write/send entry point. Socket
 * and perf attachments still need the synchronous program ownership guards.
 */
static void restrict_network_administration(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct data[2];
	unsigned int bit = 1U << CAP_NET_ADMIN;

	if (prctl(PR_CAPBSET_DROP, CAP_NET_ADMIN, 0, 0, 0) ||
	    syscall(SYS_capget, &header, data))
		fail("read network-administration capability", getpid());
	data[0].effective &= ~bit;
	data[0].permitted &= ~bit;
	data[0].inheritable &= ~bit;
	if (syscall(SYS_capset, &header, data) ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		fail("restrict network-administration capability", getpid());
}

int main(int argc, char **argv)
{
	unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP |
				PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
				PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC |
				PTRACE_O_TRACEEXIT | PTRACE_O_EXITKILL;
	sigset_t previous_signals;
	struct traced_task *task;
	char path[PATH_MAX];
	bool syscall_exit;
	int gate[2];
	char ignored;
	FILE *pid_file;

	if (argc < 4 || strcmp(argv[2], "--")) {
		fprintf(stderr, "usage: %s OUTPUT_DIR -- COMMAND [ARGS...]\n",
			argv[0]);
		return 2;
	}
	output_directory = argv[1];
	if (snprintf(path, sizeof(path), "%s/resources.jsonl",
		     output_directory) >= (int)sizeof(path)) {
		errno = ENAMETOOLONG;
		fail("observation output path", 0);
	}
	/* Reusing an old journal must never reuse a stale completion receipt.
	 */
	inventory = fopen(path, "wex");
	if (!inventory)
		fail("create a new observation journal", 0);
	atexit(write_completion);
	if (pipe2(gate, O_CLOEXEC) < 0)
		fail("open observation start gate", 0);
	sigemptyset(&observer_signals);
	sigaddset(&observer_signals, SIGTERM);
	sigaddset(&observer_signals, SIGINT);
	sigaddset(&observer_signals, SIGHUP);
	sigaddset(&observer_signals, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &observer_signals, &previous_signals))
		fail("block observer signals", 0);
	root_pid = fork();
	if (root_pid < 0)
		fail("fork observed command", 0);
	if (!root_pid) {
		close(gate[1]);
		if (read(gate[0], &ignored, 1) < 0)
			_exit(125);
		close(gate[0]);
		if (sigprocmask(SIG_SETMASK, &previous_signals, NULL))
			_exit(125);
		restrict_network_administration();
		install_filter();
		execvp(argv[3], &argv[3]);
		perror("exec observed command");
		_exit(127);
	}
	close(gate[0]);
	if (ptrace(PTRACE_SEIZE, root_pid, NULL, (void *)options) < 0 ||
	    ptrace(PTRACE_INTERRUPT, root_pid, NULL, NULL) < 0)
		fail("attach before observed command starts", root_pid);
	task = wait_event(&syscall_exit);
	if (!task || task->pid != root_pid)
		fail("wait for initial trace stop", root_pid);
	snprintf(path, sizeof(path), "%s/agent.pid", output_directory);
	pid_file = fopen(path, "wex");
	if (!pid_file || fprintf(pid_file, "%d\n", root_pid) < 0 ||
	    fclose(pid_file))
		fail("publish observed process ID", root_pid);
	close(gate[1]);
	resume_task(task, false);
	while (tasks_remaining()) {
		task = wait_event(&syscall_exit);
		if (!task)
			continue;
		if (task->operation)
			observe_operations();
		else
			resume_task(task, false);
	}
	if (fclose(inventory))
		fail("close BPF resource record", root_pid);
	complete = true;
	return root_status;
}
