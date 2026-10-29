#!/usr/bin/env bash
#
# Copyright 2026 The HuaTuo Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# Purpose: Prepare the guest and run every integration scenario individually.
# Caller: qemu-2-run-in-vm.sh streams this helper to the guest over SSH.
# Environment:
# - HOME: Used to add the user's Go binary directory to PATH.
# - PATH: Extended with system and user Go binary directories.
# Parameters:
# - Optional --prepare-only or --test-only; omitted runs both phases.
# Examples:
# - run-in-vm.sh  # prepare the guest and run the integration suite

set -euo pipefail

vm_log() {
	printf '[%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"
}

vm_log_error() {
	vm_log "$*" >&2
}

print_sys_info() {
	uname -a
	[[ ! -f /etc/os-release ]] || cat /etc/os-release
	lscpu || true
	free -h
	df -h
	ip addr show || true
	docker version || true
	docker image ls --digests || true
	crictl version || true
	crictl images --digests || true
	kubectl get nodes -o wide || true
	kubectl get pods -A || true
}

# Some images (e.g. anolis8.10) neither run cloud-init nor auto-grow their
# root partition, so the extra space requested with --disk-size stays
# invisible to the guest. Grow the root partition and filesystem to fill the
# disk. Best effort: distros that already grew report NOCHANGE.
grow_root_filesystem() {
	local root_device filesystem parent partition output
	filesystem=$(findmnt -n -o FSTYPE /)
	case "$filesystem" in
	ext4 | xfs) ;;
	*)
		vm_log "rootfs grow skipped: unsupported filesystem $filesystem"
		return 0
		;;
	esac
	root_device=$(findmnt -n -o SOURCE /)
	# findmnt reports a btrfs root as "/dev/vda3[/root]"; never let that
	# suffix reach readlink -f, which treats the embedded "/" as a path
	# separator and fails (fatal under set -e).
	root_device=${root_device%%\[*}
	root_device=$(readlink -f "$root_device" 2> /dev/null || printf '%s' "$root_device")
	if [[ ! -f /sys/class/block/${root_device##*/}/partition ]]; then
		vm_log "rootfs grow skipped: $root_device is not a direct partition"
		return 0
	fi
	if ! command -v growpart > /dev/null 2>&1; then
		vm_log_error "rootfs grow skipped: growpart is not installed"
		return 0
	fi
	parent=$(lsblk -n -o PKNAME "$root_device")
	partition=$(< "/sys/class/block/${root_device##*/}/partition")
	[[ -n "$parent" && "$partition" =~ ^[0-9]+$ ]] || {
		vm_log_error "cannot identify root partition for $root_device"
		return 1
	}
	vm_log "growing root partition $root_device on /dev/$parent"
	if output=$(growpart "/dev/$parent" "$partition" 2>&1); then
		vm_log "$output"
	elif [[ "$output" == NOCHANGE:* ]]; then
		vm_log "$output"
	else
		vm_log_error "root partition expansion failed: $output"
		return 1
	fi
	case "$filesystem" in
	ext4) resize2fs "$root_device" ;;
	xfs) xfs_growfs / ;;
	esac
	lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT "/dev/$parent"
	df -h /
}

configure_proxy() {
	local guest_hostname guest_ip proxy_port=11008
	if ! timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/$1' _ "$proxy_port" 2> /dev/null; then
		return
	fi
	guest_hostname=$(hostname)
	guest_ip=$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}')
	export http_proxy="http://127.0.0.1:${proxy_port}"
	export https_proxy="$http_proxy"
	export HTTP_PROXY="$http_proxy"
	export HTTPS_PROXY="$http_proxy"
	export all_proxy="socks5://127.0.0.1:${proxy_port}"
	export ALL_PROXY="$all_proxy"
	export no_proxy="127.0.0.1,localhost,${guest_ip},${guest_hostname},10.96.0.0/12,10.244.0.0/16,.svc,.cluster.local"
	export NO_PROXY="$no_proxy"
}

install_test_dependencies() {
	local os_id os_like package_manager package
	local -a deb_packages=(curl gdb fio mdadm xfsprogs build-essential libelf-dev kmod "linux-headers-$(uname -r)")
	local -a rpm_packages=(
		curl gdb fio mdadm xfsprogs gcc make elfutils-libelf-devel kmod kernel-headers
		"kernel-devel-$(uname -r)"
	)
	local -a missing_packages=()
	local -a package_options=()

	# Add temporary dependencies here until the VM image includes them.
	source /etc/os-release
	os_id=${ID,,}
	os_like=${ID_LIKE:-}
	os_like=${os_like,,}
	case " ${os_id} ${os_like} " in
	*ubuntu* | *debian*)
		for package in "${deb_packages[@]}"; do
			dpkg-query -W -f='${Status}' "$package" 2> /dev/null \
				| grep -q 'ok installed' || missing_packages+=("$package")
		done
		((${#missing_packages[@]} == 0)) && return
		export DEBIAN_FRONTEND=noninteractive
		apt-get -o DPkg::Lock::Timeout=300 update
		apt-get -o DPkg::Lock::Timeout=300 install -y --no-install-recommends \
			"${missing_packages[@]}"
		;;
	*fedora* | *rhel* | *centos* | *rocky* | *openeuler* | *anolis* | *opencloudos*)
		for package in "${rpm_packages[@]}"; do
			rpm -q "$package" > /dev/null 2>&1 || missing_packages+=("$package")
		done
		((${#missing_packages[@]} == 0)) && return
		if command -v dnf > /dev/null 2>&1; then
			package_manager=dnf
		elif command -v yum > /dev/null 2>&1; then
			package_manager=yum
		else
			vm_log_error "no RPM package manager found for $ID"
			return 1
		fi
		# Rocky's EPEL repository is unrelated to kernel module builds and its
		# mirror metadata is less reliable than the base repositories.
		if [[ "$os_id" == rocky ]]; then
			package_options+=(--disablerepo='epel*')
		fi
		# The full suite needs fio from everything. Avoid downloading unrelated
		# source, debug and EPOL metadata when the OS repository lacks a package.
		if [[ "$os_id" == openeuler ]]; then
			package_options+=(--disablerepo='*' --enablerepo=OS --enablerepo=everything)
		fi
		if ! "$package_manager" "${package_options[@]}" install -y "${missing_packages[@]}"; then
			[[ "$os_id" != openeuler ]] || return 1
			((${#package_options[@]})) || return 1
			vm_log "install with restricted repositories failed; retrying with all repositories"
			"$package_manager" install -y "${missing_packages[@]}"
		fi
		;;
	*)
		vm_log_error "unsupported guest package family: ID=$ID ID_LIKE=${ID_LIKE:-}"
		return 1
		;;
	esac
}

install_temporary_go_tools() {
	local tool command_name package attempt installed version
	local -a tools=(
		'oapi-codegen|github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen'
	)
	for tool in "${tools[@]}"; do
		command_name=${tool%%|*}
		package=${tool#*|}
		if command -v "$command_name" > /dev/null 2>&1; then
			version=$("$command_name" -version | awk 'NF {value=$0} END {print value}')
			[[ "$version" != v2.7.2 ]] || continue
		fi
		installed=false
		for attempt in 1 2 3; do
			if (cd /mnt/host && timeout 300 env GOTOOLCHAIN=local \
				go build -mod=vendor -o "/usr/local/bin/$command_name" "$package"); then
				installed=true
				break
			fi
			sleep $((attempt * 2))
		done
		[[ "$installed" == true ]] || {
			vm_log_error "failed to install temporary Go tool: $package"
			return 1
		}
		version=$("$command_name" -version | awk 'NF {value=$0} END {print value}')
		[[ "$version" == v2.7.2 ]] || {
			vm_log_error "unexpected $command_name version after installation: $version"
			return 1
		}
	done
}

prefetch_storage_images() {
	source integration/lib_storage.sh
	local image
	mkdir -p _output/storage-image-prefetch
	for image in "${STORAGE_ES7_IMAGE}" "${STORAGE_OPENSEARCH_IMAGE}"; do
		vm_log "preloading storage image: ${image}"
		timeout 5m docker pull "${image}" > "_output/storage-image-prefetch/${image##*/}.log" 2>&1 &
		storage_prefetch_pids+=("$!")
	done
}

stop_storage_image_prefetch() {
	local status=$? pid
	trap - EXIT
	for pid in "${storage_prefetch_pids[@]}"; do
		# Only signal jobs still owned by this shell; completed PIDs may be reused.
		if jobs -pr | grep -qx "${pid}"; then kill "${pid}" 2> /dev/null || true; fi
		wait "${pid}" 2> /dev/null || vm_log "storage image prefetch did not finish successfully; see _output/storage-image-prefetch"
	done
	exit "${status}"
}

# The runner prints log heads; retain late service errors before VM cleanup.
dump_integration_failure_logs() {
	local case_log=$1 workspace logfile
	while IFS= read -r workspace; do
		[[ -d "$workspace" ]] || continue
		while IFS= read -r -d '' logfile; do
			vm_log "failure log tail: $logfile"
			tail -n 200 "$logfile" || true
		done < <(find "$workspace" -type f -name '*.log' -print0)
	done < <(awk '/artifacts preserved at / {print $NF}' "$case_log" | sort -u)
}

run_full_integration() {
	local script case_log status completed=0 failures=0
	local -a scripts=(integration/test_*.sh)
	[[ -f "${scripts[0]}" ]] || {
		vm_log_error "no integration scripts selected"
		return 1
	}
	mkdir -p _output/full-integration
	vm_log "harness=$(git rev-parse HEAD) integration workers=1 expected_cases=${#scripts[@]}"
	for script in "${scripts[@]}"; do
		case_log="_output/full-integration/${script##*/}.log"
		status=0
		vm_log "integration case begin=${script##*/}"
		bash integration/run.sh -j 1 "${script##*/}" 2>&1 | tee "$case_log" || status=$?
		completed=$((completed + 1))
		vm_log "integration case end=${script##*/} runner_status=$status"
		if ((status != 0)); then
			failures=$((failures + 1))
			dump_integration_failure_logs "$case_log"
		fi
	done
	vm_log "integration selected=${#scripts[@]} executed=$completed failed_runs=$failures"
	((failures == 0))
}

run_guest_tests() {
	configure_proxy
	export PATH="/usr/local/go/bin:${HOME}/go/bin:${PATH}"
	export GOCACHE=/root/.cache/go-build
	if [[ ${1:-} != --test-only ]]; then
		grow_root_filesystem
		print_sys_info
		install_test_dependencies
	fi
	# CI restores the Go cache after growing the filesystem, before any Go builds.
	if [[ ${1:-} == --prepare-only ]]; then exit 0; fi
	cd /mnt/host
	if [[ ! -f _output/portable-generated.commit ]]; then
		install_temporary_go_tools
	fi
	export JAVA_PROFILER_DOCKER_IMAGE=eclipse-temurin:17-jdk
	export JAVA_PROFILER_CONTAINERD_IMAGE=docker.io/library/eclipse-temurin:17-jdk
	export NATIVE_PROFILER_DOCKER_IMAGE=busybox:1.36.1
	export NATIVE_PROFILER_CONTAINERD_IMAGE=docker.io/library/busybox:1.36.1
	export NATIVE_PROFILER_TEST_PRIVILEGED_CONTAINER=1

	pwd
	ls -alh .
	git config --global --add safe.directory /mnt/host

	# Sourced regression fixtures retain the normal make-test contract.
	vm_log '⬅️⬅️⬅️ Running tests...'

	# Hide image downloads behind compilation and integration. Compatibility cases
	# still perform their normal pull checks, including when prefetch fails.
	storage_prefetch_pids=()
	trap stop_storage_image_prefetch EXIT
	prefetch_storage_images
	make install-tools
	local make_target=test
	if [[ ${vm_full_integration:-false} == true ]]; then make_target=build; fi
	if [[ -f _output/portable-generated.commit ]]; then
		make "${make_target}" SKIP_PORTABLE_GENERATION=1
	else
		make "${make_target}"
	fi
	if [[ ${vm_full_integration:-false} == true ]]; then run_full_integration; fi

	vm_log '✅✅✅ Tests passed.'
}

# Keep the CI selection out of child cases, including guest-entry self-tests.
if [[ ${BASH_SOURCE[0]:-$0} == "$0" ]]; then
	declare +x vm_full_integration=true
	run_guest_tests "$@"
fi
