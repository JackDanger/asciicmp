package main

import (
	"fmt"
	"log"
	"net"
	"os"
  "runtime"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	fmt.Println("starting ...")
	defer fmt.Println("... done")

	// 0.000052 socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) = 3 <0.000019>
	// 0.000050 socket(AF_INET, SOCK_DGRAM, IPPROTO_IP) = 5 <0.000018>
  // 1 == iana.ProtocolICMP
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 1)
	if err != nil {
    fmt.Printf("main.go:25 %#v\n", err)
		log.Fatal(err)
	}

	// 0.000050 connect(5, {sa_family=AF_INET, sin_port=htons(1025), sin_addr=inet_addr("127.0.0.1")}, 16) = 0 <0.000019>
	if runtime.GOOS == "darwin"  {
    // 	ProtocolICMP           = 1   // Internet Control Message
    // const sysIP_STRIPHDR = 0x17 // for now only darwin supports this option
		if err := syscall.SetsockoptInt(s, 1, 0x17, 1); err != nil {
      fmt.Printf("main.go:35 %#v\n", err)
			syscall.Close(s)
			log.Fatal(err)
		}
	}

	//  0.000049 setsockopt(3, SOL_RAW, ICMP_FILTER, ~(1<<ICMP_ECHOREPLY|1<<ICMP_DEST_UNREACH|1<<ICMP_SOURCE_QUENCH|1<<ICMP_REDIRECT|1<<ICMP_TIME_EXCEEDED|1<<ICMP_PARAMETERPROB), 4) = 0 <0.000019>
	//  0.000054 setsockopt(3, SOL_IP, IP_RECVERR, [1], 4) = 0 <0.000018>
	//  0.000053 setsockopt(3, SOL_SOCKET, SO_SNDBUF, [324], 4) = 0 <0.000019>
	//  0.000052 setsockopt(3, SOL_SOCKET, SO_RCVBUF, [65536], 4) = 0 <0.000019>
	//  0.000051 getsockopt(3, SOL_SOCKET, SO_RCVBUF, [131072], [4]) = 0 <0.000019>
	//  0.000053 fstat(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0 <0.000019>
	//  0.000053 write(1, "PING localhost (127.0.0.1) 56(84) bytes of data.\n", 49PING localhost (127.0.0.1) 56(84) bytes of data.
	// 49 <0.000026>
	//  0.000059 setsockopt(3, SOL_SOCKET, SO_TIMESTAMP, [1], 4) = 0 <0.000019>
	//  0.000052 setsockopt(3, SOL_SOCKET, SO_SNDTIMEO, "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) = 0 <0.000018>
	//  0.000051 setsockopt(3, SOL_SOCKET, SO_RCVTIMEO, "\1\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) = 0 <0.000019>
	//  0.000051 getpid()                  = 26711 <0.000018>
	//  0.000053 rt_sigaction(SIGINT, {sa_handler=0x55ae687c1440, sa_mask=[], sa_flags=SA_RESTORER|SA_INTERRUPT, sa_restorer=0x7f8a511d4f20}, NULL, 8) = 0 <0.000019>
	//  0.000057 rt_sigaction(SIGALRM, {sa_handler=0x55ae687c1440, sa_mask=[], sa_flags=SA_RESTORER|SA_INTERRUPT, sa_restorer=0x7f8a511d4f20}, NULL, 8) = 0 <0.000019>
	//  0.000053 rt_sigaction(SIGQUIT, {sa_handler=0x55ae687c1430, sa_mask=[], sa_flags=SA_RESTORER|SA_INTERRUPT, sa_restorer=0x7f8a511d4f20}, NULL, 8) = 0 <0.000019>
	//  0.000053 rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0 <0.000018>
	//  0.000050 ioctl(1, TCGETS, {B9600 opost isig icanon echo ...}) = 0 <0.000018>
	//  0.000053 ioctl(1, TIOCGWINSZ, {ws_row=29, ws_col=238, ws_xpixel=0, ws_ypixel=0}) = 0 <0.000018>
	//  0.000052 sendto(3, "\10\0\330\230hW\0\1\256\227g\\\0\0\0\0\331G\t\0\0\0\0\0\20\21\22\23\24\25\26\27\30\31\32\33\34\35\36\37 !\"#$%&'()*+,-./01234567", 64, 0, {sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, 16) = 64 <0.000027>
	//  0.000081 recvmsg(3, {msg_name={sa_family=AF_INET, sin_port=htons(0), sin_addr=inet_addr("127.0.0.1")}, msg_namelen=128->16, msg_iov=[{iov_base="E\0\0T\372m\0\0@\1\2029\177\0\0\1\177\0\0\1\0\0\340\230hW\0\1\256\227g\\\0\0\0\0\331G\t\0\0\0\0\0\20\21\22\23\24\25\26\27\30\31\32\33\34\35\36\37 !\"#$%&'()*+,-./01234567", iov_len=192}], msg_iovlen=1, msg_control=[{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=SCM_TIMESTAMP, cmsg_data={tv_sec=1550292910, tv_usec=608278}}], msg_controllen=32, msg_flags=0}, 0) = 84 <0.000018>

	c, err := icmp.ListenPacket("ip4:icmp", "192.168.0.1")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-R-U-THERE"),
		},
	}
	wb, err := wm.Marshal(nil)

	if err != nil {
		log.Fatal(err)
	}
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: net.ParseIP("ff02::1"), Zone: "en0"}); err != nil {
		log.Fatal(err)
	}

	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		log.Fatal(err)
	}
	rm, err := icmp.ParseMessage(58, rb[:n])
	if err != nil {
		log.Fatal(err)
	}
	switch rm.Type {
	case ipv4.ICMPTypeEchoReply:
		log.Printf("got reflection from %v", peer)
	default:
		log.Printf("got %+v; want echo reply", rm)
	}
}
