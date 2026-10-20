// Package pcapgen 将 HTTP 请求/响应文本合成为经典 libpcap 文件，
// 包含完整的 TCP 三次握手、数据传输（MSS 分段）与四次挥手。
// 参考 wireshark/离线 pcap 生成器实现。
package pcapgen

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"
)

const mss = 1460

var (
	srcMac = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMac = []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
)

type Options struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
}

func (o Options) normalize() Options {
	if o.SrcIP == "" || net.ParseIP(o.SrcIP).To4() == nil {
		o.SrcIP = "192.168.1.100"
	}
	if o.DstIP == "" || net.ParseIP(o.DstIP).To4() == nil {
		o.DstIP = "192.168.1.200"
	}
	if o.SrcPort == 0 {
		o.SrcPort = 51472
	}
	if o.DstPort == 0 {
		o.DstPort = 80
	}
	return o
}

type builder struct {
	buf      *bytes.Buffer
	ts       uint64 // ms
	src, dst [4]byte
	o        Options
	cSeq     uint32
	sSeq     uint32
}

// HTTP 生成仅含单个 HTTP 会话（请求+响应）的 pcap
func HTTP(o Options, request, response []byte) []byte {
	o = o.normalize()
	src := net.ParseIP(o.SrcIP).To4()
	dst := net.ParseIP(o.DstIP).To4()
	b := &builder{buf: new(bytes.Buffer), ts: uint64(time.Now().UnixMilli()), o: o}
	copy(b.src[:], src)
	copy(b.dst[:], dst)
	var isn [8]byte
	rand.Read(isn[:])
	b.cSeq = binary.BigEndian.Uint32(isn[:4])
	b.sSeq = binary.BigEndian.Uint32(isn[4:])

	// pcap 全局头
	binary.Write(b.buf, binary.LittleEndian, uint32(0xa1b2c3d4))
	binary.Write(b.buf, binary.LittleEndian, uint16(2))
	binary.Write(b.buf, binary.LittleEndian, uint16(4))
	binary.Write(b.buf, binary.LittleEndian, int32(0))
	binary.Write(b.buf, binary.LittleEndian, uint32(0))
	binary.Write(b.buf, binary.LittleEndian, uint32(65535))
	binary.Write(b.buf, binary.LittleEndian, uint32(1)) // LINKTYPE_ETHERNET

	opts := []byte{2, 4, 0x05, 0xb4, 4, 2, 1, 1} // MSS + SACK permitted + NOP,NOP

	// 三次握手
	b.send(true, 0x02, nil, opts)  // SYN
	b.send(false, 0x12, nil, opts) // SYN-ACK
	b.send(true, 0x10, nil, nil)   // ACK

	// 请求（MSS 分段，最后一段带 PSH）
	for off := 0; off < len(request); {
		n := mss
		if off+n > len(request) {
			n = len(request) - off
		}
		flags := uint8(0x10)
		if off+n == len(request) {
			flags |= 0x08
		}
		b.send(true, flags, request[off:off+n], nil)
		off += n
	}
	b.send(false, 0x10, nil, nil) // ACK

	// 响应（MSS 分段）
	for off := 0; off < len(response); {
		n := mss
		if off+n > len(response) {
			n = len(response) - off
		}
		flags := uint8(0x10)
		if off+n == len(response) {
			flags |= 0x08
		}
		b.send(false, flags, response[off:off+n], nil)
		off += n
	}
	b.send(true, 0x10, nil, nil) // ACK

	// 四次挥手
	b.send(true, 0x11, nil, nil)  // FIN+ACK client
	b.send(false, 0x10, nil, nil) // ACK
	b.send(false, 0x11, nil, nil) // FIN+ACK server
	b.send(true, 0x10, nil, nil)  // ACK

	return b.buf.Bytes()
}

// send 发送一个 TCP 包；fromClient 决定方向与 seq/ack 维护
func (b *builder) send(fromClient bool, flags uint8, payload, opts []byte) {
	var seq, ack uint32
	if fromClient {
		seq, ack = b.cSeq, b.sSeq
	} else {
		seq, ack = b.sSeq, b.cSeq
	}
	tcp := b.tcp(fromClient, seq, ack, flags, payload, opts)
	ip := b.ip(fromClient, tcp)
	b.frame(fromClient, ip)
	// 推进 seq：SYN/FIN 占一个序号
	n := uint32(len(payload))
	if flags&0x02 != 0 || flags&0x01 != 0 {
		n++
	}
	if fromClient {
		b.cSeq += n
	} else {
		b.sSeq += n
	}
	b.ts++
}

func (b *builder) tcp(fromClient bool, seq, ack uint32, flags uint8, payload, opts []byte) []byte {
	// 选项 4 字节对齐
	pad := (4 - len(opts)%4) % 4
	hdrLen := 20 + len(opts) + pad
	out := make([]byte, hdrLen+len(payload))
	sp, dp := b.o.SrcPort, b.o.DstPort
	if !fromClient {
		sp, dp = dp, sp
	}
	binary.BigEndian.PutUint16(out[0:2], sp)
	binary.BigEndian.PutUint16(out[2:4], dp)
	binary.BigEndian.PutUint32(out[4:8], seq)
	binary.BigEndian.PutUint32(out[8:12], ack)
	out[12] = uint8(hdrLen / 4 << 4)
	out[13] = flags
	binary.BigEndian.PutUint16(out[14:16], 65535)
	copy(out[20:], opts)
	copy(out[hdrLen:], payload)

	// 伪头部校验和
	src, dst := b.src, b.dst
	if !fromClient {
		src, dst = b.dst, b.src
	}
	ph := make([]byte, 0, 12+len(out))
	ph = append(ph, src[:]...)
	ph = append(ph, dst[:]...)
	ph = append(ph, 0, 6, 0, 0)
	binary.BigEndian.PutUint16(ph[10:12], uint16(len(out)))
	sum := checksum(append(ph, out...))
	binary.BigEndian.PutUint16(out[16:18], sum)
	return out
}

func (b *builder) ip(fromClient bool, payload []byte) []byte {
	out := make([]byte, 20+len(payload))
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	out[8] = 64
	out[9] = 6
	src, dst := b.src, b.dst
	if !fromClient {
		src, dst = b.dst, b.src
	}
	copy(out[12:16], src[:])
	copy(out[16:20], dst[:])
	binary.BigEndian.PutUint16(out[10:12], checksum(out[:20]))
	copy(out[20:], payload)
	return out
}

func (b *builder) frame(fromClient bool, ip []byte) {
	eth := make([]byte, 14+len(ip))
	src, dst := srcMac, dstMac
	if !fromClient {
		src, dst = dstMac, srcMac
	}
	copy(eth[0:6], dst)
	copy(eth[6:12], src)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	copy(eth[14:], ip)

	binary.Write(b.buf, binary.LittleEndian, uint32(b.ts/1000))
	binary.Write(b.buf, binary.LittleEndian, uint32((b.ts%1000)*1000))
	binary.Write(b.buf, binary.LittleEndian, uint32(len(eth)))
	binary.Write(b.buf, binary.LittleEndian, uint32(len(eth)))
	b.buf.Write(eth)
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
