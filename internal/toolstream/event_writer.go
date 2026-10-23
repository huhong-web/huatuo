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

package toolstream

import (
	"context"
	"errors"
	"sync"
	"time"
)

// EventCloseTimeout bounds best-effort event-stream finalization.
const EventCloseTimeout = 5 * time.Second

// EventWriter owns an event connection until Close. Cancellation interrupts a
// blocked Write by closing the connection, so End delivery is not guaranteed
// after cancellation. Serialize Write and Close calls.
type EventWriter struct {
	sendFrame        func(context.Context, any, SendOptions) error
	closeClient      func() error
	runCtx           context.Context
	sendCtx          context.Context
	stopCancellation func() bool
	connectionOnce   sync.Once
	connectionErr    error
	finishOnce       sync.Once
	finishErr        error
}

// NewEventWriter takes ownership of a connected client for one run. Binding
// cancellation once avoids adding a cancellation callback for every sample.
func NewEventWriter(ctx context.Context, client *Client) *EventWriter {
	writer := &EventWriter{
		sendFrame:   client.Send,
		closeClient: client.Close,
		runCtx:      ctx,
		sendCtx:     context.WithoutCancel(ctx),
	}
	writer.stopCancellation = context.AfterFunc(ctx, func() { _ = writer.closeConnection() })
	return writer
}

// Write sends one event while the owning run is active.
func (w *EventWriter) Write(event any) error {
	if err := w.runCtx.Err(); err != nil {
		return err
	}
	if err := w.sendFrame(w.sendCtx, event, SendOptions{}); err != nil {
		return errors.Join(err, w.runCtx.Err())
	}
	return nil
}

// Close sends End within the earlier of the run deadline and EventCloseTimeout
// on normal completion, and always closes the connection. A canceled run only
// closes: its stream may already have been interrupted. Repeated calls return
// the original close result.
func (w *EventWriter) Close() error {
	w.finishOnce.Do(func() {
		w.stopCancellation()
		if w.runCtx.Err() != nil {
			w.finishErr = w.closeConnection()
			return
		}
		deadline := time.Now().Add(EventCloseTimeout)
		if runDeadline, ok := w.runCtx.Deadline(); ok && runDeadline.Before(deadline) {
			deadline = runDeadline
		}
		ctx, cancel := context.WithDeadline(w.sendCtx, deadline)
		defer cancel()
		w.finishErr = errors.Join(
			w.sendFrame(ctx, nil, SendOptions{End: true}),
			w.closeConnection(),
		)
	})
	return w.finishErr
}

func (w *EventWriter) closeConnection() error {
	w.connectionOnce.Do(func() { w.connectionErr = w.closeClient() })
	return w.connectionErr
}
