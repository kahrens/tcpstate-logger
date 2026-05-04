//go:build linux

package main

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otlploggrpc "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

func setupOTel(ctx context.Context, endpoint, serviceName string, insecure bool) (otellog.Logger, func(context.Context) error, error) {
	opts := []otlploggrpc.Option{
		otlploggrpc.WithEndpoint(endpoint),
	}
	if insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}

	exp, err := otlploggrpc.New(ctx, opts...)
	if err != nil {
		return nil, nil, fmt.Errorf("creating OTLP gRPC log exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", serviceName)),
	)
	if err != nil {
		res = resource.Default()
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
		sdklog.WithResource(res),
	)

	logger := provider.Logger("tcpstate-logger",
		otellog.WithInstrumentationVersion("0.1.0"),
	)

	return logger, provider.Shutdown, nil
}

func emitTCPStateEvent(ctx context.Context, logger otellog.Logger, ev *bpfEvent) {
	src := addrString(ev.Saddr[:], ev.Family)
	dst := addrString(ev.Daddr[:], ev.Family)
	comm := commString(ev.Comm)

	body := fmt.Sprintf("%s[%d] %s:%d -> %s:%d  %s -> %s",
		comm, ev.Pid,
		src, ev.Sport,
		dst, ev.Dport,
		tcpStateName(ev.Oldstate),
		tcpStateName(ev.Newstate),
	)

	var r otellog.Record
	r.SetTimestamp(time.Unix(0, bootTimeNs+int64(ev.TimestampNs)))
	r.SetObservedTimestamp(time.Now())
	r.SetSeverity(otellog.SeverityInfo)
	r.SetSeverityText("INFO")
	r.SetBody(otellog.StringValue(body))
	r.AddAttributes(
		otellog.String("network.local.address", src),
		otellog.Int("network.local.port", int(ev.Sport)),
		otellog.String("network.peer.address", dst),
		otellog.Int("network.peer.port", int(ev.Dport)),
		otellog.String("network.transport", "tcp"),
		otellog.String("tcp.state.old", tcpStateName(ev.Oldstate)),
		otellog.String("tcp.state.new", tcpStateName(ev.Newstate)),
		otellog.Int("process.pid", int(ev.Pid)),
		otellog.String("process.executable.name", comm),
	)

	logger.Emit(ctx, r)
}

func emitUDPDatagramEvent(ctx context.Context, logger otellog.Logger, ev *bpfEvent) {
	src := addrString(ev.Saddr[:], ev.Family)
	dst := addrString(ev.Daddr[:], ev.Family)
	comm := commString(ev.Comm)

	dir := "send"
	localAddr, localPort := src, int(ev.Sport)
	peerAddr, peerPort := dst, int(ev.Dport)
	if ev.EventType == eventUDPRecv {
		dir = "recv"
		localAddr, localPort = dst, int(ev.Dport)
		peerAddr, peerPort = src, int(ev.Sport)
	}

	body := fmt.Sprintf("%s[%d] %s:%d -> %s:%d  UDP %s %d bytes",
		comm, ev.Pid,
		src, ev.Sport,
		dst, ev.Dport,
		dir, ev.Datalen,
	)

	var r otellog.Record
	r.SetTimestamp(time.Unix(0, bootTimeNs+int64(ev.TimestampNs)))
	r.SetObservedTimestamp(time.Now())
	r.SetSeverity(otellog.SeverityInfo)
	r.SetSeverityText("INFO")
	r.SetBody(otellog.StringValue(body))
	r.AddAttributes(
		otellog.String("network.local.address", localAddr),
		otellog.Int("network.local.port", localPort),
		otellog.String("network.peer.address", peerAddr),
		otellog.Int("network.peer.port", peerPort),
		otellog.String("network.transport", "udp"),
		otellog.String("udp.direction", dir),
		otellog.Int("udp.datagram.size", int(ev.Datalen)),
		otellog.Int("process.pid", int(ev.Pid)),
		otellog.String("process.executable.name", comm),
	)

	logger.Emit(ctx, r)
}

var tcpStates = map[uint8]string{
	1:  "TCP_ESTABLISHED",
	2:  "TCP_SYN_SENT",
	3:  "TCP_SYN_RECV",
	4:  "TCP_FIN_WAIT1",
	5:  "TCP_FIN_WAIT2",
	6:  "TCP_TIME_WAIT",
	7:  "TCP_CLOSE",
	8:  "TCP_CLOSE_WAIT",
	9:  "TCP_LAST_ACK",
	10: "TCP_LISTEN",
	11: "TCP_CLOSING",
	12: "TCP_NEW_SYN_RECV",
}

func tcpStateName(state uint8) string {
	if n, ok := tcpStates[state]; ok {
		return n
	}
	return fmt.Sprintf("TCP_STATE_%d", state)
}

func commString(comm [16]int8) string {
	var b [16]byte
	for i, c := range comm {
		b[i] = byte(c)
	}
	n := bytes.IndexByte(b[:], 0)
	if n < 0 {
		n = 16
	}
	return string(b[:n])
}
