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

/* Keep an external socket alive and generate attachment activity. Shell owns
 * process orchestration and all assertions on the reported kernel state. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;

static int bpf_call(unsigned int command, union bpf_attr *attributes)
{
	return syscall(SYS_bpf, command, attributes, sizeof(*attributes));
}

static int create_program(unsigned int type)
{
	struct bpf_insn instructions[] = {
		{.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0},
		{.code = BPF_JMP | BPF_EXIT},
	};
	union bpf_attr attributes = {
		.prog_type = type,
		.insn_cnt = 2,
		.insns = (uint64_t)(uintptr_t)instructions,
		.license = (uint64_t)(uintptr_t)"GPL",
		.prog_name = "socket_workload",
	};

	return bpf_call(BPF_PROG_LOAD, &attributes);
}

static int program_id(int fd, unsigned int *id)
{
	struct bpf_prog_info info = {0};
	union bpf_attr attributes = {
		.info.bpf_fd = fd,
		.info.info_len = sizeof(info),
		.info.info = (uint64_t)(uintptr_t)&info,
	};

	if (bpf_call(BPF_OBJ_GET_INFO_BY_FD, &attributes))
		return -1;
	*id = info.id;
	return 0;
}

static int socket_address(const char *path, struct sockaddr_un *address)
{
	memset(address, 0, sizeof(*address));
	address->sun_family = AF_UNIX;
	if (snprintf(address->sun_path, sizeof(address->sun_path), "%s",
		     path) >= (int)sizeof(address->sun_path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	return 0;
}

static int send_socket(int connection, int socket_fd)
{
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(int))];
	} control = {0};
	char byte = 'S';
	struct iovec vector = {&byte, sizeof(byte)};
	struct msghdr message = {.msg_iov = &vector,
				 .msg_iovlen = 1,
				 .msg_control = control.bytes,
				 .msg_controllen = sizeof(control)};
	struct cmsghdr *header = CMSG_FIRSTHDR(&message);

	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(socket_fd));
	memcpy(CMSG_DATA(header), &socket_fd, sizeof(socket_fd));
	return sendmsg(connection, &message, MSG_NOSIGNAL | MSG_DONTWAIT) < 0
		       ? -1
		       : 0;
}

static int receive_socket(const char *path)
{
	union {
		struct cmsghdr align;
		char bytes[CMSG_SPACE(sizeof(int))];
	} control = {0};
	struct sockaddr_un address;
	char byte;
	struct iovec vector = {&byte, sizeof(byte)};
	struct msghdr message = {.msg_iov = &vector,
				 .msg_iovlen = 1,
				 .msg_control = control.bytes,
				 .msg_controllen = sizeof(control)};
	struct cmsghdr *header;
	int connection;
	int fd = -1;

	if (socket_address(path, &address))
		return -1;
	connection = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (connection < 0)
		return -1;
	if (connect(connection, (struct sockaddr *)&address, sizeof(address)) ||
	    recvmsg(connection, &message, MSG_CMSG_CLOEXEC) <= 0)
		goto out;
	header = CMSG_FIRSTHDR(&message);
	if (!header || header->cmsg_level != SOL_SOCKET ||
	    header->cmsg_type != SCM_RIGHTS ||
	    header->cmsg_len != CMSG_LEN(sizeof(fd)) ||
	    (message.msg_flags & MSG_CTRUNC)) {
		errno = EPROTO;
		goto out;
	}
	memcpy(&fd, CMSG_DATA(header), sizeof(fd));
out:
	close(connection);
	return fd;
}

static void on_term(int signal)
{
	(void)signal;
	stopped = 1;
}

static int serve_socket(const char *path, const char *ready)
{
	struct sockaddr_in local = {.sin_family = AF_INET,
				    .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
	struct sigaction action = {.sa_handler = on_term};
	struct sockaddr_un address;
	unsigned int socket_id;
	unsigned int perf_id;
	int program = -1;
	int perf = -1;
	int listener = -1;
	int shared = -1;
	int connection;
	int enabled = 1;
	int status = -1;
	FILE *file;

	if (socket_address(path, &address))
		return -1;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGTERM, &action, NULL))
		return -1;
	program = create_program(BPF_PROG_TYPE_SOCKET_FILTER);
	perf = create_program(BPF_PROG_TYPE_PERF_EVENT);
	shared = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (program < 0 || perf < 0 || shared < 0 || listener < 0)
		goto out;
	if (setsockopt(shared, SOL_SOCKET, SO_REUSEPORT, &enabled,
		       sizeof(enabled)) ||
	    bind(shared, (struct sockaddr *)&local, sizeof(local)) ||
	    bind(listener, (struct sockaddr *)&address, sizeof(address)) ||
	    listen(listener, 8) || program_id(program, &socket_id) ||
	    program_id(perf, &perf_id))
		goto out;
	file = fopen(ready, "wex");
	if (!file)
		goto out;
	status = fprintf(file,
			 "{\"socket_program_id\":%u,\"perf_program_id\":%u}\n",
			 socket_id, perf_id);
	if (fclose(file) || status < 0) {
		status = -1;
		goto out;
	}
	status = 0;
	while (!stopped) {
		connection = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
		if (connection < 0) {
			if (errno == EINTR)
				continue;
			status = -1;
			break;
		}
		if (send_socket(connection, shared))
			status = -1;
		close(connection);
		if (status)
			break;
	}
out:
	if (listener >= 0)
		close(listener);
	if (shared >= 0)
		close(shared);
	if (perf >= 0)
		close(perf);
	if (program >= 0)
		close(program);
	unlink(path);
	return status;
}

static int report_socket(int fd)
{
	socklen_t length = 0;
	int status;

	status = getsockopt(fd, SOL_SOCKET, SO_GET_FILTER, NULL, &length);
	if (!status) {
		printf("{\"attached\":%s}\n", length ? "true" : "false");
		return 0;
	}
	/* Linux cannot dump an eBPF filter through the classic filter API. */
	if (errno == EACCES) {
		puts("{\"attached\":true}");
		return 0;
	}
	return -1;
}

static int netlink_activity(const char *mode)
{
	struct {
		struct nlmsghdr header;
		struct ifinfomsg link;
	} request = {
		.header = {.nlmsg_len = sizeof(request),
			   .nlmsg_type = RTM_GETLINK,
			   .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP |
					  NLM_F_ACK},
		.link = {.ifi_family = AF_UNSPEC},
	};
	struct sockaddr_nl destination = {.nl_family = AF_NETLINK};
	struct iovec vector = {&request, sizeof(request)};
	struct mmsghdr message = {
		.msg_hdr = {.msg_name = &destination,
			    .msg_namelen = sizeof(destination),
			    .msg_iov = &vector,
			    .msg_iovlen = 1}};
	struct pollfd ready = {.events = POLLIN};
	struct nlmsgerr response;
	unsigned char bytes[8192];
	struct nlmsghdr header;
	ssize_t length;
	int status;
	int fd;

	if (strstr(mode, "config"))
		request.header.nlmsg_type = RTM_SETLINK;
	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    NETLINK_ROUTE);
	if (fd < 0)
		return -1;
	if (strstr(mode, "mmsg"))
		status = sendmmsg(fd, &message, 1, MSG_DONTWAIT);
	else if (strstr(mode, "msg"))
		status = sendmsg(fd, &message.msg_hdr, MSG_DONTWAIT);
	else
		status = sendto(fd, &request, sizeof(request), MSG_DONTWAIT,
				(struct sockaddr *)&destination,
				sizeof(destination));
	if (status < 0)
		goto out;
	ready.fd = fd;
	if (poll(&ready, 1, 3000) != 1) {
		errno = ETIMEDOUT;
		status = -1;
		goto out;
	}
	length = recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT);
	if (length < (ssize_t)sizeof(header)) {
		errno = EPROTO;
		status = -1;
		goto out;
	}
	memcpy(&header, bytes, sizeof(header));
	if (header.nlmsg_type == NLMSG_ERROR &&
	    length >= (ssize_t)(sizeof(header) + sizeof(response))) {
		memcpy(&response, bytes + sizeof(header), sizeof(response));
		printf("{\"kernel_error\":%d}\n", -response.error);
	} else {
		printf("{\"kernel_error\":0,\"reply_type\":%u}\n",
		       header.nlmsg_type);
	}
	status = 0;
out:
	close(fd);
	return status;
}

static int socket_activity(const char *mode, const char *path, unsigned int id)
{
	union bpf_attr attributes = {.prog_id = id};
	struct perf_event_attr perf = {.type = PERF_TYPE_SOFTWARE,
				       .size = sizeof(perf),
				       .config = PERF_COUNT_SW_CPU_CLOCK,
				       .disabled = 1};
	struct sockaddr_in address;
	socklen_t length = sizeof(address);
	int program = -1;
	int target = -1;
	int enabled = 1;
	int status = -1;
	int fd;

	fd = receive_socket(path);
	if (fd < 0)
		return -1;
	if (!strcmp(mode, "plain")) {
		if (!setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &enabled,
				sizeof(enabled)) &&
		    !getsockname(fd, (struct sockaddr *)&address, &length))
			status = sendto(fd, "S", 1, MSG_DONTWAIT,
					(struct sockaddr *)&address, length) < 0
					 ? -1
					 : 0;
	} else if (!strcmp(mode, "classic_attach") ||
		   !strcmp(mode, "classic_tun")) {
		struct sock_filter instruction = {.code = BPF_RET | BPF_K};
		struct sock_fprog filter = {.len = 1, .filter = &instruction};

		if (!strcmp(mode, "classic_attach")) {
			status = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
					    &filter, sizeof(filter));
		} else {
			target = open("/dev/null", O_RDWR | O_CLOEXEC);
			if (target >= 0)
				status = ioctl(target, TUNATTACHFILTER,
					       &filter);
		}
	} else if (!strcmp(mode, "inspect")) {
		status = report_socket(fd);
	} else if (!strcmp(mode, "detach")) {
		status = setsockopt(fd, SOL_SOCKET, SO_DETACH_FILTER, &enabled,
				    sizeof(enabled));
	} else {
		if (!strncmp(mode, "owned", 5))
			program = create_program(
				!strcmp(mode, "owned_perf")
					? BPF_PROG_TYPE_PERF_EVENT
					: BPF_PROG_TYPE_SOCKET_FILTER);
		else
			program = bpf_call(BPF_PROG_GET_FD_BY_ID, &attributes);
		if (program < 0)
			goto out;
		if (!strcmp(mode, "borrowed_query")) {
			status = program_id(program, &id);
		} else if (!strcmp(mode, "borrowed_export")) {
			int pair[2];

			if (!socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
					pair)) {
				status = send_socket(pair[0], program);
				close(pair[0]);
				close(pair[1]);
			}
		} else if (!strcmp(mode, "owned_test_run") ||
			   !strcmp(mode, "borrowed_test_run")) {
			unsigned char packet[64] = {0};

			memset(&attributes, 0, sizeof(attributes));
			attributes.test.prog_fd = program;
			attributes.test.data_in = (uint64_t)(uintptr_t)packet;
			attributes.test.data_size_in = sizeof(packet);
			attributes.test.repeat = 1;
			status = bpf_call(BPF_PROG_TEST_RUN, &attributes);
		} else if (!strcmp(mode, "borrowed_perf") ||
			   !strcmp(mode, "owned_perf") ||
			   !strcmp(mode, "borrowed_perf_highbits")) {
			unsigned long request = PERF_EVENT_IOC_SET_BPF;

			if (!strcmp(mode, "borrowed_perf_highbits"))
				request |= 1UL << 32;
			target = syscall(SYS_perf_event_open, &perf, 0, -1, -1,
					 PERF_FLAG_FD_CLOEXEC);
			if (target >= 0)
				status = syscall(SYS_ioctl, target, request,
						 program);
		} else if (!strcmp(mode, "borrowed_tun_steering") ||
			   !strcmp(mode, "borrowed_tun_filter")) {
			target = open("/dev/null", O_RDWR | O_CLOEXEC);
			if (target >= 0)
				status = ioctl(target,
					       !strcmp(mode,
						       "borrowed_tun_filter")
						       ? TUNSETFILTEREBPF
						       : TUNSETSTEERINGEBPF,
					       &program);
		} else if (!strcmp(mode, "borrowed_attach_highbits")) {
			status = syscall(SYS_setsockopt, fd,
					 (1UL << 32) | SOL_SOCKET,
					 (1UL << 32) | SO_ATTACH_BPF, &program,
					 sizeof(program));
		} else if (!strcmp(mode, "borrowed_attach") ||
			   !strcmp(mode, "borrowed_reuseport") ||
			   !strcmp(mode, "owned_attach") ||
			   !strcmp(mode, "owned_detach")) {
			status = setsockopt(fd, SOL_SOCKET,
					    !strcmp(mode, "borrowed_reuseport")
						    ? SO_ATTACH_REUSEPORT_EBPF
						    : SO_ATTACH_BPF,
					    &program, sizeof(program));
			if (!status && !strcmp(mode, "owned_detach"))
				status = setsockopt(fd, SOL_SOCKET,
						    SO_DETACH_FILTER, &enabled,
						    sizeof(enabled));
		} else {
			errno = EINVAL;
		}
	}
out:
	if (target >= 0)
		close(target);
	if (program >= 0)
		close(program);
	close(fd);
	return status;
}

static int report_capability(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct data[2];
	int bounded;

	if (syscall(SYS_capget, &header, data))
		return -1;
	bounded = prctl(PR_CAPBSET_READ, CAP_NET_ADMIN, 0, 0, 0);
	if (bounded < 0)
		return -1;
	printf("{\"effective\":%u,\"permitted\":%u,\"inheritable\":%u,"
	       "\"bounded\":%d,\"no_new_privs\":%d}\n",
	       !!(data[0].effective & (1U << CAP_NET_ADMIN)),
	       !!(data[0].permitted & (1U << CAP_NET_ADMIN)),
	       !!(data[0].inheritable & (1U << CAP_NET_ADMIN)), bounded,
	       prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0));
	return 0;
}

int main(int argc, char **argv)
{
	const struct rlimit memlock = {RLIM_INFINITY, RLIM_INFINITY};
	unsigned long id = 0;
	char *end;
	int status;

	if (argc < 3 || argc > 4) {
		fprintf(stderr,
			"usage: %s MODE SOCKET_PATH [PROGRAM_ID|READY_FILE]\n",
			argv[0]);
		return 2;
	}
	if (setrlimit(RLIMIT_MEMLOCK, &memlock)) {
		perror("raise socket workload memlock limit");
		return 1;
	}
	if (!strcmp(argv[1], "capability")) {
		status = report_capability();
	} else if (!strcmp(argv[1], "serve") && argc == 4) {
		status = serve_socket(argv[2], argv[3]);
	} else if (!strncmp(argv[1], "netlink_", 8)) {
		status = netlink_activity(argv[1]);
	} else {
		if (argc == 4) {
			id = strtoul(argv[3], &end, 10);
			if (!*argv[3] || *end || id > UINT32_MAX)
				return 2;
		}
		status = socket_activity(argv[1], argv[2], id);
	}
	if (status < 0) {
		fprintf(stderr, "socket workload %s failed: %s\n", argv[1],
			strerror(errno));
		return 1;
	}
	return 0;
}
