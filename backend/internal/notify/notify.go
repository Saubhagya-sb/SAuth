// Package notify delivers out-of-band messages (currently just OTP codes).
// Real email/SMS transports slot in behind OTPSender later; for now dev builds
// use LogSender and tests use RecordingSender.
package notify

import (
	"context"
	"log/slog"
	"sync"
)

type Channel string

const (
	ChannelEmail Channel = "email"
	ChannelSMS   Channel = "sms"
)

type OTPSender interface {
	SendOTP(ctx context.Context, channel Channel, destination, code, purpose string) error
}

// LogSender writes the code to the logs. Development only.
type LogSender struct{}

func (LogSender) SendOTP(_ context.Context, channel Channel, destination, code, purpose string) error {
	slog.Warn("otp dispatched via dev log sender — do not use in production",
		"channel", channel, "destination", destination, "purpose", purpose, "code", code)
	return nil
}

// RecordingSender keeps the last code per destination for assertions in tests.
type RecordingSender struct {
	mu   sync.Mutex
	last map[string]string
}

func NewRecordingSender() *RecordingSender {
	return &RecordingSender{last: make(map[string]string)}
}

func (r *RecordingSender) SendOTP(_ context.Context, _ Channel, destination, code, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last[destination] = code
	return nil
}

func (r *RecordingSender) Code(destination string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last[destination]
}
