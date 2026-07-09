// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package events

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"path"
	"time"

	internalconfig "huatuo-bamai/internal/config"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/internal/toolstream"
	"huatuo-bamai/pkg/tracing"
	"huatuo-bamai/pkg/types"
)

//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/tcp_retrans.c -o $BPF_DIR/tcp_retrans.o

type tcpRetransTracing struct{}

func init() {
	tracing.RegisterEventTracing("tcp_retrans", newTCPRetrans)
	toolstream.RegisterDefault[*types.TCPRetransTracing]("tcpretrans", handleTCPRetransEvent)
}

func newTCPRetrans() (*tracing.EventTracingAttr, error) {
	return &tracing.EventTracingAttr{
		TracingData: &tcpRetransTracing{},
		Interval:    10,
		Flag:        tracing.FlagTracing,
	}, nil
}

// Start launches tcpretrans as a subprocess and waits for it to finish.
// Events are received via the default toolstream server registered in init.
func (c *tcpRetransTracing) Start(ctx context.Context) error {
	args := []string{
		"--bpf-path", path.Join(internalconfig.CoreBpfDir, "tcp_retrans.o"),
		"--output-storage", toolstream.DefaultSockPath,
	}

	if cfg.TcpRetrans.Filter != "" {
		args = append(args, "--filter", cfg.TcpRetrans.Filter)
	}

	cmd := exec.Command(path.Join(internalconfig.CoreBinDir, "tcpretrans"), args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("start tcpretrans: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("start tcpretrans: stderr pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start tcpretrans: %w", err)
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			log.Warnf("tcpretrans: %s", scanner.Text())
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			log.Warnf("tcpretrans: %s", scanner.Text())
		}
	}()

	log.Infof("tcpretrans started pid=%d", cmd.Process.Pid)

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		<-done
		log.Info("tcpretrans stopped")
		return nil
	case werr := <-done:
		if werr != nil {
			return fmt.Errorf("tcpretrans exited: %w", werr)
		}
		log.Info("tcpretrans exited")
		return nil
	}
}

func handleTCPRetransEvent(_ *toolstream.Session, ev *types.TCPRetransTracing) error {
	if ev.ContainerID == "" {
		ev.ContainerID = pod.ResolveContainerIDFromMeta(pod.ContainerMeta{
			MemoryCgroupCSSAddr: ev.MemcgCssAddr,
			NetNamespaceCookie:  ev.NetNamespaceCookie,
			NetNamespaceInode:   uint64(ev.NetNamespaceInode),
		})
	}

	if ev.DropLocation == "" {
		causal, _ := globalDropCache.correlate(ev)
		ev.DropLocation = causalToDropLocation(causal)
	}

	return tracing.Save(&tracing.WriteRequest{
		TracerName:  "tcp_retrans",
		ContainerID: ev.ContainerID,
		TracerTime:  time.Now(),
		TracerData:  ev,
	})
}
