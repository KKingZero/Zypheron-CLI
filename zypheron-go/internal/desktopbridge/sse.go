package desktopbridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SSEEvent is one parsed frame from the desktop's /v1/events stream.
// See electron/services/control-api-service.ts:'/v1/events' for the
// emitter side. ID is propagated back via Last-Event-ID on reconnect.
type SSEEvent struct {
	ID   string
	Type string
	Data string
}

// SSEHandler receives each parsed event in order. Returning an error from
// the handler stops the stream and returns control to the caller.
type SSEHandler func(ev SSEEvent) error

// sseHeartbeatTimeout is set to 2x the desktop's 15s heartbeat interval. If
// no data (event or `:keepalive` comment) arrives in this window we treat
// the connection as dead and reconnect.
const sseHeartbeatTimeout = 35 * time.Second

// Stream subscribes to /v1/events and dispatches each frame to handler.
// It implements reconnect-with-Last-Event-ID per architecture decision 13.
// Blocks until ctx is cancelled, the handler returns an error, or the
// underlying refresh path fails terminally (ErrUnauthorized).
func (c *Client) Stream(ctx context.Context, handler SSEHandler) error {
	lastEventID := ""
	backoff := 500 * time.Millisecond
	const maxBackoff = 30 * time.Second

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := c.streamOnce(ctx, &lastEventID, handler)
		switch {
		case err == nil:
			// Server closed cleanly. Reconnect immediately with no penalty.
			backoff = 500 * time.Millisecond
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return err
		case errors.Is(err, ErrUnauthorized):
			return err
		case errors.Is(err, errSSEHandlerAbort):
			return nil
		default:
			// Transport / parse error — back off and reconnect.
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

var errSSEHandlerAbort = errors.New("sse handler requested abort")

// streamOnce establishes one HTTP connection to /v1/events and pumps frames
// until the stream ends or a heartbeat is missed. Updates *lastEventID as
// frames are observed so reconnects resume at the right point.
func (c *Client) streamOnce(ctx context.Context, lastEventID *string, handler SSEHandler) error {
	// SSE is long-lived, so use a dedicated client without the Client's
	// general-purpose 30s timeout — connection-level deadlines kill streams.
	streamClient := &http.Client{Timeout: 0}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ep.URL+"/v1/events", nil)
	if err != nil {
		return fmt.Errorf("build sse request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken())
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "zypheron-cli/"+ClientVersion)
	if *lastEventID != "" {
		req.Header.Set("Last-Event-ID", *lastEventID)
	}

	resp, err := streamClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect sse: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		// Reuse the Client's refresh path so the next reconnect uses a
		// fresh access token. The next loop iteration will retry.
		if refreshErr := c.refresh(ctx); refreshErr != nil {
			_ = DeleteTokens()
			return fmt.Errorf("%w: %v", ErrUnauthorized, refreshErr)
		}
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		if code := readErrorCode(resp.Body); code != "" {
			return fmt.Errorf("sse status HTTP %d (%s)", resp.StatusCode, code)
		}
		return fmt.Errorf("sse status HTTP %d", resp.StatusCode)
	}

	return parseEventStream(ctx, resp.Body, lastEventID, handler)
}

// parseEventStream reads SSE frames from r per the WHATWG event-stream
// format. The desktop emits frames in the canonical (event, id, data) shape
// plus `:keepalive` comment lines. We treat any inbound data (including the
// comment) as a heartbeat — missing data beyond sseHeartbeatTimeout = dead.
func parseEventStream(ctx context.Context, r io.Reader, lastEventID *string, handler SSEHandler) error {
	reader := bufio.NewReader(r)

	type frame struct {
		event string
		id    string
		data  strings.Builder
	}
	cur := frame{}

	// readCh runs the actual line read in a goroutine so we can layer a
	// heartbeat deadline on top of bufio without bypassing it.
	type readResult struct {
		line string
		err  error
	}
	readCh := make(chan readResult, 1)
	// done signals the reader goroutine to abandon any in-flight send.
	// Closed by the deferred cleanup below; needed per the 2026-05-27
	// security review (M1) to prevent the goroutine from blocking on a
	// channel send forever when parseEventStream returns early.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			line, err := reader.ReadString('\n')
			select {
			case readCh <- readResult{line, err}:
			case <-done:
				return
			}
			if err != nil {
				return
			}
		}
	}()

	heartbeat := time.NewTimer(sseHeartbeatTimeout)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-heartbeat.C:
			return errors.New("sse heartbeat timeout — reconnecting")
		case res := <-readCh:
			if res.err != nil {
				if errors.Is(res.err, io.EOF) {
					return nil
				}
				return fmt.Errorf("read sse stream: %w", res.err)
			}
			// Any inbound byte counts as a heartbeat — keepalive comments
			// included.
			if !heartbeat.Stop() {
				select {
				case <-heartbeat.C:
				default:
				}
			}
			heartbeat.Reset(sseHeartbeatTimeout)

			line := strings.TrimRight(res.line, "\r\n")
			if line == "" {
				// Frame terminator.
				if cur.event != "" || cur.data.Len() > 0 {
					ev := SSEEvent{ID: cur.id, Type: cur.event, Data: cur.data.String()}
					if ev.ID != "" {
						*lastEventID = ev.ID
					}
					if err := handler(ev); err != nil {
						return errSSEHandlerAbort
					}
				}
				cur = frame{}
				continue
			}
			// Comments (`:keepalive`, etc.) are ignored after the heartbeat
			// reset above.
			if strings.HasPrefix(line, ":") {
				continue
			}

			name, value, hadColon := strings.Cut(line, ":")
			if hadColon {
				value = strings.TrimPrefix(value, " ")
			}
			switch name {
			case "event":
				cur.event = value
			case "id":
				cur.id = value
			case "data":
				if cur.data.Len() > 0 {
					cur.data.WriteByte('\n')
				}
				cur.data.WriteString(value)
			}
		}
	}
}
