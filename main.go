//go:build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux -type event bpf ./bpf/tcpstate.c -- -I/usr/include/bpf -D__TARGET_ARCH_x86

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	eventTCPState uint8 = 0
	eventUDPSend  uint8 = 1
	eventUDPRecv  uint8 = 2
)

var (
	flagEndpoint    = flag.String("endpoint", "localhost:4317", "OTLP gRPC endpoint (OTel Collector or Loki)")
	flagInsecure    = flag.Bool("insecure", true, "disable TLS for OTLP gRPC connection")
	flagServiceName = flag.String("service-name", "tcpstate-logger", "OTel resource service.name")
	flagStdout      = flag.Bool("stdout", false, "print events to stdout in addition to OTLP export")
	bootTimeNs      = getBootTimeNs()
)

func main() {
	log.Printf("bootTimeNs = %d", bootTimeNs)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock rlimit: %v", err)
	}

	logger, shutdown, err := setupOTel(ctx, *flagEndpoint, *flagServiceName, *flagInsecure)
	if err != nil {
		log.Fatalf("setting up OTel: %v", err)
	}
	defer func() {
		if err := shutdown(context.Background()); err != nil {
			log.Printf("OTel shutdown: %v", err)
		}
	}()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.HandleInetSockSetState, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint sock/inet_sock_set_state: %v\n"+
			"  hint: sudo mount -t tracefs tracefs /sys/kernel/tracing", err)
	}
	defer tp.Close()

	kpSend, err := link.Kprobe("udp_sendmsg", objs.HandleUdpSendmsg, nil)
	if err != nil {
		log.Fatalf("attaching kprobe udp_sendmsg: %v", err)
	}
	defer kpSend.Close()

	kpRecvEntry, err := link.Kprobe("udp_recvmsg", objs.HandleUdpRecvmsg, nil)
	if err != nil {
		log.Fatalf("attaching kprobe udp_recvmsg: %v", err)
	}
	defer kpRecvEntry.Close()

	kpRecvRet, err := link.Kretprobe("udp_recvmsg", objs.HandleUdpRecvmsgRet, nil)
	if err != nil {
		log.Fatalf("attaching kretprobe udp_recvmsg: %v", err)
	}
	defer kpRecvRet.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ring buffer: %v", err)
	}

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	log.Printf("probes attached, exporting to %s", *flagEndpoint)

	var ev bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("ring buffer read: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &ev); err != nil {
			log.Printf("parsing event: %v", err)
			continue
		}
		switch ev.EventType {
		case eventTCPState:
			if *flagStdout {
				printTCPEvent(&ev)
			}
			emitTCPStateEvent(ctx, logger, &ev)
		case eventUDPSend, eventUDPRecv:
			if *flagStdout {
				printUDPEvent(&ev)
			}
			emitUDPDatagramEvent(ctx, logger, &ev)
		}
	}
}

func printTCPEvent(ev *bpfEvent) {
	src := addrString(ev.Saddr[:], ev.Family)
	dst := addrString(ev.Daddr[:], ev.Family)
	fmt.Printf("%d %s[%d] %s:%d -> %s:%d  %s -> %s\n",
		bootTimeNs+int64(ev.TimestampNs),
		commString(ev.Comm),
		ev.Pid,
		src, ev.Sport,
		dst, ev.Dport,
		tcpStateName(ev.Oldstate),
		tcpStateName(ev.Newstate),
	)
}

func printUDPEvent(ev *bpfEvent) {
	src := addrString(ev.Saddr[:], ev.Family)
	dst := addrString(ev.Daddr[:], ev.Family)
	dir := "send"
	if ev.EventType == eventUDPRecv {
		dir = "recv"
	}
	fmt.Printf("%d %s[%d] %s:%d -> %s:%d  UDP %s %d bytes\n",
		bootTimeNs+int64(ev.TimestampNs),
		commString(ev.Comm),
		ev.Pid,
		src, ev.Sport,
		dst, ev.Dport,
		dir,
		ev.Datalen,
	)
}

func addrString(b []byte, family uint16) string {
	if family == 10 { // AF_INET6
		return net.IP(b[:16]).String()
	}
	return net.IP(b[:4]).String()
}

func getBootTimeNs() int64 {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		panic("syscall.Sysinfo:" + err.Error())
	}
	return time.Now().UnixNano() - int64(info.Uptime)*int64(time.Second)
}
