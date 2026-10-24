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

/* Exercise real BPF resources and report observations; Shell owns assertions.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/bpf.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *directory;
static volatile sig_atomic_t stopped;
static atomic_bool race_stop;
extern char **environ;

enum {
	WORKLOAD_MAP_UPDATE_BATCH = 26,
	WORKLOAD_PROG_BIND_MAP = 35,
};

static int bpf_call(int command, union bpf_attr *attributes)
{
	return syscall(SYS_bpf, command, attributes, sizeof(*attributes));
}

static int create_map(void)
{
	union bpf_attr attributes = {
		.map_type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint64_t),
		.max_entries = 1,
		.map_name = "leak_workload",
	};

	return bpf_call(BPF_MAP_CREATE, &attributes);
}

static int create_program(void)
{
	struct bpf_insn instructions[] = {
		{.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0},
		{.code = BPF_JMP | BPF_EXIT},
	};
	union bpf_attr attributes = {
		.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT,
		.insn_cnt = sizeof(instructions) / sizeof(instructions[0]),
		.insns = (uint64_t)(uintptr_t)instructions,
		.license = (uint64_t)(uintptr_t)"GPL",
		.prog_name = "leak_workload",
	};

	return bpf_call(BPF_PROG_LOAD, &attributes);
}

static int load_map_program(const char *pin)
{
	struct bpf_insn instructions[] = {
		{.code = BPF_LD | BPF_DW | BPF_IMM,
		 .dst_reg = BPF_REG_1,
		 .src_reg = BPF_PSEUDO_MAP_FD},
		{0},
		{.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0},
		{.code = BPF_JMP | BPF_EXIT},
	};
	union bpf_attr attributes = {.pathname = (uint64_t)(uintptr_t)pin};
	int program;
	int map;

	map = bpf_call(BPF_OBJ_GET, &attributes);
	if (map < 0)
		return -1;
	instructions[0].imm = map;
	memset(&attributes, 0, sizeof(attributes));
	attributes.prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
	attributes.insn_cnt = sizeof(instructions) / sizeof(instructions[0]);
	attributes.insns = (uint64_t)(uintptr_t)instructions;
	attributes.license = (uint64_t)(uintptr_t)"GPL";
	program = bpf_call(BPF_PROG_LOAD, &attributes);
	close(map);
	if (program < 0)
		return -1;
	close(program);
	return 0;
}

static int format_pin_path(char *path, const char *name)
{
	if (snprintf(path, PATH_MAX, "%s/%s", directory, name) >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static int pin_fd(int fd, const char *name)
{
	union bpf_attr attributes = {.bpf_fd = fd};
	char path[PATH_MAX];

	if (format_pin_path(path, name))
		return -1;
	attributes.pathname = (uint64_t)(uintptr_t)path;
	return bpf_call(BPF_OBJ_PIN, &attributes);
}

static int create_pinned_map(void)
{
	int status;
	int fd;

	fd = create_map();
	if (fd < 0)
		return -1;
	status = pin_fd(fd, "map");
	close(fd);
	return status;
}

static int open_source_pin(const char *source, const char *name)
{
	union bpf_attr attributes = {0};
	char path[PATH_MAX];

	if (snprintf(path, sizeof(path), "%s/%s", source, name) >=
	    (int)sizeof(path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	attributes.pathname = (uint64_t)(uintptr_t)path;
	return bpf_call(BPF_OBJ_GET, &attributes);
}

static int create_reference_map(unsigned int type, int inner)
{
	union bpf_attr attributes = {
		.map_type = type,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint32_t),
		.max_entries = 1,
		.inner_map_fd = type == BPF_MAP_TYPE_PROG_ARRAY ? 0 : inner,
	};

	return bpf_call(BPF_MAP_CREATE, &attributes);
}

static int create_reference_source(unsigned int type)
{
	int status = -1;
	int inner;
	int outer;

	inner = type == BPF_MAP_TYPE_PROG_ARRAY ? create_program()
						: create_map();
	if (inner < 0)
		return -1;
	outer = create_reference_map(type, inner);
	if (outer >= 0) {
		status = pin_fd(inner, "inner");
		if (!status)
			status = pin_fd(outer, "outer");
		close(outer);
	}
	close(inner);
	return status;
}

static int update_reference_batch(int outer, int inner, uint32_t key)
{
	/* Stable batch UAPI layout, including builds with pre-5.6 headers. */
	struct {
		uint64_t in_batch;
		uint64_t out_batch;
		uint64_t keys;
		uint64_t values;
		uint32_t count;
		uint32_t map_fd;
		uint64_t elem_flags;
		uint64_t flags;
	} batch = {.keys = (uint64_t)(uintptr_t)&key,
		   .values = (uint64_t)(uintptr_t)&inner,
		   .count = 1,
		   .map_fd = outer};
	union bpf_attr attributes = {0};

	memcpy(&attributes, &batch, sizeof(batch));
	return bpf_call(WORKLOAD_MAP_UPDATE_BATCH, &attributes);
}

static int bind_program_map(int program, int map)
{
	struct {
		uint32_t prog_fd;
		uint32_t map_fd;
		uint32_t flags;
	} binding = {.prog_fd = program, .map_fd = map};
	union bpf_attr attributes = {0};

	memcpy(&attributes, &binding, sizeof(binding));
	return bpf_call(WORKLOAD_PROG_BIND_MAP, &attributes);
}

static int reference_operation(const char *mode, const char *source)
{
	union bpf_attr attributes = {0};
	struct bpf_map_info info = {0};
	uint32_t value = 0;
	uint32_t key = 0;
	int status = -1;
	int inner = -1;
	int outer;

	outer = open_source_pin(source, !strcmp(mode, "borrowed_program_bind")
						? "prog"
						: "outer");
	if (outer < 0)
		return -1;
	if (strcmp(mode, "reference_hold") &&
	    strcmp(mode, "reference_lookup") &&
	    strcmp(mode, "reference_clear")) {
		inner = open_source_pin(source, "inner");
		if (inner < 0)
			goto out;
	}
	if (!strcmp(mode, "owned_reference_clear")) {
		attributes.info.bpf_fd = outer;
		attributes.info.info_len = sizeof(info);
		attributes.info.info = (uint64_t)(uintptr_t)&info;
		if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attributes))
			goto out;
		close(outer);
		outer = create_reference_map(info.type, inner);
		if (outer < 0)
			goto out;
	}
	memset(&attributes, 0, sizeof(attributes));
	attributes.map_fd = outer;
	attributes.key = (uint64_t)(uintptr_t)&key;
	attributes.value = (uint64_t)(uintptr_t)&inner;
	if (!strcmp(mode, "reference_hold")) {
		status = 0;
	} else if (!strcmp(mode, "reference_lookup")) {
		attributes.value = (uint64_t)(uintptr_t)&value;
		status = bpf_call(BPF_MAP_LOOKUP_ELEM, &attributes);
		if (!status)
			printf("{\"present\":true,\"id\":%u}\n", value);
		else if (errno == ENOENT) {
			puts("{\"present\":false}");
			status = 0;
		}
	} else if (!strcmp(mode, "reference_clear")) {
		attributes.value = 0;
		status = bpf_call(BPF_MAP_DELETE_ELEM, &attributes);
	} else if (!strcmp(mode, "borrowed_reference_batch")) {
		status = update_reference_batch(outer, inner, key);
	} else if (!strcmp(mode, "borrowed_program_bind")) {
		status = bind_program_map(outer, inner);
	} else if (!strcmp(mode, "reference_fill") ||
		   !strcmp(mode, "borrowed_reference") ||
		   !strcmp(mode, "owned_reference_clear")) {
		status = bpf_call(BPF_MAP_UPDATE_ELEM, &attributes);
		if (!status && !strcmp(mode, "owned_reference_clear")) {
			attributes.value = 0;
			status = bpf_call(BPF_MAP_DELETE_ELEM, &attributes);
		}
	} else {
		errno = EINVAL;
	}
out:
	if (inner >= 0)
		close(inner);
	if (outer >= 0)
		close(outer);
	return status;
}

static int update_borrowed_data(const char *source)
{
	union bpf_attr attributes = {0};
	uint64_t value = 42;
	uint32_t key = 0;
	int status;
	int fd;

	attributes.pathname = (uint64_t)(uintptr_t)source;
	fd = bpf_call(BPF_OBJ_GET, &attributes);
	if (fd < 0)
		return -1;
	memset(&attributes, 0, sizeof(attributes));
	attributes.map_fd = fd;
	attributes.key = (uint64_t)(uintptr_t)&key;
	attributes.value = (uint64_t)(uintptr_t)&value;
	status = bpf_call(BPF_MAP_UPDATE_ELEM, &attributes);
	close(fd);
	return status;
}

static int borrow_map(const char *source, const char *mode)
{
	union bpf_attr attributes = {.pathname = (uint64_t)(uintptr_t)source};
	char from[PATH_MAX];
	char to[PATH_MAX];
	int status;
	int fd;

	fd = bpf_call(BPF_OBJ_GET, &attributes);
	if (fd < 0)
		return -1;
	status = pin_fd(fd, "borrowed");
	close(fd);
	if (status || !strcmp(mode, "borrowed"))
		return status;
	if (format_pin_path(from, "borrowed") || format_pin_path(to, "renamed"))
		return -1;
	if (!strcmp(mode, "borrowed_directory_rename")) {
		if (mkdir(to, 0700))
			return -1;
		if (format_pin_path(to, "renamed/borrowed"))
			return -1;
		if (rename(from, to))
			return -1;
		if (format_pin_path(from, "renamed") ||
		    format_pin_path(to, "moved"))
			return -1;
	}
	return rename(from, to);
}

static void on_term(int signal)
{
	(void)signal;
	stopped = 1;
}

static int wait_for_term(const char *ready_file)
{
	struct sigaction action = {.sa_handler = on_term};
	sigset_t blocked;
	sigset_t previous;
	int fd;

	sigemptyset(&blocked);
	sigaddset(&blocked, SIGTERM);
	if (sigprocmask(SIG_BLOCK, &blocked, &previous))
		return -1;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL))
		return -1;
	fd = open(ready_file, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	close(fd);
	while (!stopped)
		sigsuspend(&previous);
	return sigprocmask(SIG_SETMASK, &previous, NULL);
}

static void *close_shared_fd(void *unused)
{
	(void)unused;
	while (!atomic_load_explicit(&race_stop, memory_order_relaxed))
		close(3);
	return NULL;
}

static void *spawn_children(void *unused)
{
	char *arguments[] = {"true", NULL};
	pid_t child;

	(void)unused;
	while (!atomic_load_explicit(&race_stop, memory_order_relaxed)) {
		if (posix_spawn(&child, "/bin/true", NULL, NULL, arguments,
				environ))
			return (void *)1;
		while (waitpid(child, NULL, 0) < 0)
			if (errno != EINTR)
				return (void *)1;
	}
	return NULL;
}

int main(int argc, char **argv)
{
	const struct rlimit memlock = {RLIM_INFINITY, RLIM_INFINITY};
	union bpf_attr attributes = {0};
	void *thread_status;
	pthread_t closer;
	int status = -1;
	pid_t parent;
	pid_t child;
	int link_fd;
	int fd;
	int i;

	if (argc < 3) {
		fprintf(stderr, "usage: %s MODE PIN_DIRECTORY [BORROWED_PIN]\n",
			argv[0]);
		return 2;
	}
	/* Older kernels charge BPF memory to the UID, including the running
	 * Agent. The workload needs its own limit raised as well. */
	if (setrlimit(RLIMIT_MEMLOCK, &memlock)) {
		perror("raise BPF workload memlock limit");
		return 1;
	}
	directory = argv[2];
	if (!strcmp(argv[1], "map")) {
		status = create_pinned_map();
	} else if (!strcmp(argv[1], "reference_source")) {
		status = create_reference_source(BPF_MAP_TYPE_ARRAY_OF_MAPS);
	} else if (!strcmp(argv[1], "reference_hash_source")) {
		status = create_reference_source(BPF_MAP_TYPE_HASH_OF_MAPS);
	} else if (!strcmp(argv[1], "reference_program_source")) {
		status = create_reference_source(BPF_MAP_TYPE_PROG_ARRAY);
	} else if ((argc == 3 || argc == 4) &&
		   (!strncmp(argv[1], "reference_", 10) ||
		    !strncmp(argv[1], "borrowed_reference", 18) ||
		    !strcmp(argv[1], "borrowed_program_bind") ||
		    !strcmp(argv[1], "owned_reference_clear"))) {
		status = reference_operation(argv[1],
					     argc == 4 ? argv[3] : directory);
	} else if (!strcmp(argv[1], "borrowed_data_update") && argc == 4) {
		status = update_borrowed_data(argv[3]);
	} else if (!strcmp(argv[1], "borrowed_map_program") && argc == 4) {
		status = load_map_program(argv[3]);
	} else if (!strcmp(argv[1], "late")) {
		if (argc == 4 && wait_for_term(argv[3]) == 0)
			status = create_pinned_map();
	} else if (!strcmp(argv[1], "orphan")) {
		parent = getpid();
		child = fork();
		if (child < 0)
			return 1;
		if (child)
			return 0;
		while (getppid() == parent)
			sched_yield();
		status = create_pinned_map();
	} else if (!strcmp(argv[1], "prog") || !strcmp(argv[1], "link") ||
		   !strcmp(argv[1], "raw")) {
		fd = create_program();
		if (fd >= 0) {
			if (!strcmp(argv[1], "prog")) {
				status = pin_fd(fd, "prog");
			} else {
				attributes.raw_tracepoint.name =
					(uint64_t)(uintptr_t)"sys_enter";
				attributes.raw_tracepoint.prog_fd = fd;
				link_fd = bpf_call(BPF_RAW_TRACEPOINT_OPEN,
						   &attributes);
				if (link_fd >= 0) {
					if (!strcmp(argv[1], "raw"))
						status = 0;
					else
						status = pin_fd(link_fd,
								"link");
					close(link_fd);
				}
			}
			close(fd);
		}
	} else if ((!strcmp(argv[1], "borrowed") ||
		    !strcmp(argv[1], "borrowed_rename") ||
		    !strcmp(argv[1], "borrowed_directory_rename")) &&
		   argc == 4) {
		status = borrow_map(argv[3], argv[1]);
	} else if (!strcmp(argv[1], "hardlink") && argc == 4) {
		char path[PATH_MAX];

		if (format_pin_path(path, "borrowed"))
			return 1;
		status = link(argv[3], path);
	} else if (!strcmp(argv[1], "mount_namespace")) {
		status = unshare(CLONE_NEWNS);
	} else if (!strcmp(argv[1], "user_namespace")) {
		status = unshare(CLONE_NEWUSER);
	} else if (!strcmp(argv[1], "race") || !strcmp(argv[1], "fork_race")) {
		if (pthread_create(&closer, NULL,
				   !strcmp(argv[1], "race") ? close_shared_fd
							    : spawn_children,
				   NULL))
			return 1;
		status = 0;
		for (i = 0; i < 100; i++) {
			fd = create_map();
			if (fd < 0) {
				status = -1;
				break;
			}
			close(fd);
		}
		atomic_store_explicit(&race_stop, true, memory_order_relaxed);
		pthread_join(closer, &thread_status);
		if (thread_status)
			status = -1;
	} else if (!strcmp(argv[1], "unsupported")) {
		status = bpf_call(BPF_PROG_ATTACH, &attributes);
	} else {
		fprintf(stderr, "unsupported BPF workload: %s\n", argv[1]);
		return 2;
	}
	if (status < 0) {
		fprintf(stderr, "BPF workload %s failed: %s\n", argv[1],
			strerror(errno));
		return 1;
	}
	return 0;
}
