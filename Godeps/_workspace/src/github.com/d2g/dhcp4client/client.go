package dhcp4client

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/rocket/Godeps/_workspace/src/github.com/d2g/dhcp4"
)

const (
	// not sure why it's not in syscall for linux
	minIPHdrLen = 20
	maxIPHdrLen = 60
	udpHdrLen   = 8
	maxDHCPLen  = 576
	ip4Ver      = 0x40
	ip4FlagDF   = 0x40
)

var (
	bcastMAC = []byte{255, 255, 255, 255, 255, 255}
)

type conn interface {
	Close() error
	Send(packet dhcp4.Packet) error
	RecvFrom() ([]byte, net.IP, error)
	SetReadTimeout(t time.Duration) error
}

func chksum(p []byte, csum []byte) {
	cklen := len(p)
	s := uint32(0)
	for i := 0; i < (cklen - 1); i += 2 {
		s += uint32(p[i+1])<<8 | uint32(p[i])
	}
	if cklen&1 == 1 {
		s += uint32(p[cklen-1])
	}
	s = (s >> 16) + (s & 0xffff)
	s = s + (s >> 16)
	s = ^s

	csum[0] = uint8(s & 0xff)
	csum[1] = uint8(s >> 8)
}

func fillIPHdr(hdr []byte, payloadLen uint16) {
	// version + IHL
	hdr[0] = ip4Ver | (minIPHdrLen / 4)
	// total length
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(hdr))+payloadLen)
	// identification
	// TODO: check for err
	if _, err := rand.Read(hdr[4:5]); err != nil {
		panic(err)
	}
	// Flags+FragLen == set DF bit
	hdr[6] = ip4FlagDF
	// TTL
	hdr[8] = 64
	// Protocol
	hdr[9] = syscall.IPPROTO_UDP
	// dst IP
	copy(hdr[16:20], net.IPv4bcast.To4())
	// no compute the checksum
	chksum(hdr[0:len(hdr)], hdr[10:12])
}

func fillUDPHdr(hdr []byte, payloadLen uint16) {
	// src port
	binary.BigEndian.PutUint16(hdr[0:2], 68)
	// dest port
	binary.BigEndian.PutUint16(hdr[2:4], 67)
	// length
	binary.BigEndian.PutUint16(hdr[4:6], udpHdrLen+payloadLen)
}

func swap16(x uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], x)
	return binary.LittleEndian.Uint16(b[:])
}

// abstracts AF_PACKET
type packetConn struct {
	fd      int
	ifindex int
}

func NewPacketConn(ifindex int) (*packetConn, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(swap16(syscall.ETH_P_IP)))
	if err != nil {
		return nil, err
	}

	addr := syscall.SockaddrLinklayer{
		Ifindex:  ifindex,
		Protocol: swap16(syscall.ETH_P_IP),
	}

	if err = syscall.Bind(fd, &addr); err != nil {
		return nil, err
	}

	return &packetConn{
		fd:      fd,
		ifindex: ifindex,
	}, nil
}

func (pc *packetConn) Close() error {
	return syscall.Close(pc.fd)
}

func (pc *packetConn) Send(packet dhcp4.Packet) error {
	lladdr := syscall.SockaddrLinklayer{
		Ifindex:  pc.ifindex,
		Halen:    uint8(len(bcastMAC)),
		Protocol: swap16(syscall.ETH_P_IP),
	}
	copy(lladdr.Addr[:], bcastMAC)

	pkt := make([]byte, minIPHdrLen+udpHdrLen+len(packet))

	fillIPHdr(pkt[0:minIPHdrLen], udpHdrLen+uint16(len(packet)))
	fillUDPHdr(pkt[minIPHdrLen:minIPHdrLen+udpHdrLen], uint16(len(packet)))

	// payload
	copy(pkt[minIPHdrLen+udpHdrLen:len(pkt)], packet)

	return syscall.Sendto(pc.fd, pkt, 0, &lladdr)
}

func (pc *packetConn) RecvFrom() ([]byte, net.IP, error) {
	pkt := make([]byte, maxIPHdrLen+udpHdrLen+maxDHCPLen)
	n, _, err := syscall.Recvfrom(pc.fd, pkt, 0)
	log.Print(n, err)
	if err != nil {
		return nil, nil, err
	}

	// IP hdr len
	ihl := int(pkt[0]&0x0F) * 4
	// Source IP address
	src := net.IP(pkt[12:16])

	log.Print(ihl, src.String())

	return pkt[ihl+udpHdrLen : n], src, nil
}

func (pc *packetConn) SetReadTimeout(t time.Duration) error {
	tv := syscall.Timeval{
		Sec:  int64(t.Seconds()),
		Usec: t.Nanoseconds(),
	}
	return syscall.SetsockoptTimeval(pc.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
}

type udpConn struct {
	c *net.UDPConn
}

func NewUDPConn() (*udpConn, error) {
	address := net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 68}
	c, err := net.ListenUDP("udp4", &address)
	return &udpConn{c}, err
}

func (uc *udpConn) Close() error {
	return uc.c.Close()
}

func (uc *udpConn) Send(packet dhcp4.Packet) error {
	address := net.UDPAddr{IP: net.IPv4bcast, Port: 67}

	_, err := uc.c.WriteToUDP(packet, &address)
	//I Keep experencing what seems to be random "invalid argument" errors
	//if err != nil {
	//	log.Printf("Error:%v\n", err)
	//}
	return err
}

func (uc *udpConn) RecvFrom() ([]byte, net.IP, error) {
	readBuffer := make([]byte, maxDHCPLen)
	n, source, err := uc.c.ReadFromUDP(readBuffer)
	return readBuffer[:n], source.IP, err
}

func (uc *udpConn) SetReadTimeout(t time.Duration) error {
	return uc.c.SetReadDeadline(time.Now().Add(t))
}

type Client struct {
	MACAddress    net.HardwareAddr //The MACAddress to send in the request.
	IgnoreServers []net.IP         //List of Servers to Ignore requests from.
	Timeout       time.Duration    //Time before we timeout.
	Ifindex       int              //Interface index on which to send/recv packets
	NoBcastFlag   bool             //Don't set the Bcast flag in BOOTP Flags

	connection      conn
	connectionMutex sync.Mutex //This is to stop us renewing as we're trying to get a normal
}

/*
 * Connect Setup Connections to be used by other functions :D
 */
func (this *Client) Connect() error {
	if this.connection == nil {
		c, err := NewUDPConn()

		if err != nil {
			return err
		}

		this.connection = c
	}
	return nil
}

func (this *Client) ConnectPkt() error {
	if this.connection == nil {
		if this.Ifindex == 0 {
			return errors.New("Ifindex required with AF_PACKET sockets")
		}

		c, err := NewPacketConn(this.Ifindex)
		if err != nil {
			return err
		}

		this.connection = c
	}

	return nil
}

/*
 * Close Connections
 */
func (this *Client) Close() error {
	if this.connection != nil {
		return this.connection.Close()
	}
	return nil
}

/*
 * Send the Discovery Packet to the Broadcast Channel
 */
func (this *Client) SendDiscoverPacket() (dhcp4.Packet, error) {
	discoveryPacket := this.DiscoverPacket()
	discoveryPacket.PadToMinSize()

	return discoveryPacket, this.SendPacket(discoveryPacket)
}

/*
 * Retreive Offer...
 * Wait for the offer for a specific Discovery Packet.
 */
func (this *Client) GetOffer(discoverPacket *dhcp4.Packet) (dhcp4.Packet, error) {
	for {
		this.connection.SetReadTimeout(this.Timeout)
		readBuffer, source, err := this.connection.RecvFrom()
		if err != nil {
			return dhcp4.Packet{}, err
		}

		offerPacket := dhcp4.Packet(readBuffer)
		offerPacketOptions := offerPacket.ParseOptions()

		// Ignore Servers in my Ignore list
		for _, ignoreServer := range this.IgnoreServers {
			if source.Equal(ignoreServer) {
				continue
			}

			if offerPacket.SIAddr().Equal(ignoreServer) {
				continue
			}
		}
		log.Print(len(offerPacketOptions[dhcp4.OptionDHCPMessageType]), dhcp4.MessageType(offerPacketOptions[dhcp4.OptionDHCPMessageType][0]), offerPacket.XId())

		if len(offerPacketOptions[dhcp4.OptionDHCPMessageType]) < 1 || dhcp4.MessageType(offerPacketOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.Offer || !bytes.Equal(discoverPacket.XId(), offerPacket.XId()) {
			continue
		}

		return offerPacket, nil
	}

}

/*
 * Send Request Based On the offer Received.
 */
func (this *Client) SendRequest(offerPacket *dhcp4.Packet) (dhcp4.Packet, error) {
	requestPacket := this.RequestPacket(offerPacket)
	requestPacket.PadToMinSize()

	return requestPacket, this.SendPacket(requestPacket)
}

/*
 * Retreive Acknowledgement
 * Wait for the offer for a specific Request Packet.
 */
func (this *Client) GetAcknowledgement(requestPacket *dhcp4.Packet) (dhcp4.Packet, error) {
	for {
		this.connection.SetReadTimeout(this.Timeout)
		readBuffer, source, err := this.connection.RecvFrom()
		if err != nil {
			return dhcp4.Packet{}, err
		}

		acknowledgementPacket := dhcp4.Packet(readBuffer)
		acknowledgementPacketOptions := acknowledgementPacket.ParseOptions()

		// Ignore Servers in my Ignore list
		for _, ignoreServer := range this.IgnoreServers {
			if source.Equal(ignoreServer) {
				continue
			}

			if acknowledgementPacket.SIAddr().Equal(ignoreServer) {
				continue
			}
		}

		if !bytes.Equal(requestPacket.XId(), acknowledgementPacket.XId()) || len(acknowledgementPacketOptions[dhcp4.OptionDHCPMessageType]) < 1 || (dhcp4.MessageType(acknowledgementPacketOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.ACK && dhcp4.MessageType(acknowledgementPacketOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.NAK) {
			continue
		}

		return acknowledgementPacket, nil
	}
}

/*
 * Send a DHCP Packet.
 */
func (this *Client) SendPacket(packet dhcp4.Packet) error {
	return this.connection.Send(packet)
}

/*
 * Create Discover Packet
 */
func (this *Client) DiscoverPacket() dhcp4.Packet {
	messageid := make([]byte, 4)
	if _, err := rand.Read(messageid); err != nil {
		panic(err)
	}

	packet := dhcp4.NewPacket(dhcp4.BootRequest)
	packet.SetCHAddr(this.MACAddress)
	packet.SetXId(messageid)
	packet.SetBroadcast(!this.NoBcastFlag)

	packet.AddOption(dhcp4.OptionDHCPMessageType, []byte{byte(dhcp4.Discover)})
	//packet.PadToMinSize()
	return packet
}

/*
 * Create Request Packet
 */
func (this *Client) RequestPacket(offerPacket *dhcp4.Packet) dhcp4.Packet {
	offerOptions := offerPacket.ParseOptions()

	packet := dhcp4.NewPacket(dhcp4.BootRequest)
	packet.SetCHAddr(this.MACAddress)

	packet.SetXId(offerPacket.XId())
	packet.SetCIAddr(offerPacket.CIAddr())
	packet.SetSIAddr(offerPacket.SIAddr())

	packet.SetBroadcast(true)
	packet.AddOption(dhcp4.OptionDHCPMessageType, []byte{byte(dhcp4.Request)})
	packet.AddOption(dhcp4.OptionRequestedIPAddress, (offerPacket.YIAddr()).To4())
	packet.AddOption(dhcp4.OptionServerIdentifier, offerOptions[dhcp4.OptionServerIdentifier])

	//packet.PadToMinSize()
	return packet
}

/*
 * Create Request Packet For a Renew
 */
func (this *Client) RenewalRequestPacket(acknowledgement *dhcp4.Packet) dhcp4.Packet {
	messageid := make([]byte, 4)
	if _, err := rand.Read(messageid); err != nil {
		panic(err)
	}

	acknowledgementOptions := acknowledgement.ParseOptions()

	packet := dhcp4.NewPacket(dhcp4.BootRequest)
	packet.SetCHAddr(acknowledgement.CHAddr())

	packet.SetXId(messageid)
	packet.SetCIAddr(acknowledgement.YIAddr())
	packet.SetSIAddr(acknowledgement.SIAddr())

	packet.SetBroadcast(true)
	packet.AddOption(dhcp4.OptionDHCPMessageType, []byte{byte(dhcp4.Request)})
	packet.AddOption(dhcp4.OptionRequestedIPAddress, (acknowledgement.YIAddr()).To4())
	packet.AddOption(dhcp4.OptionServerIdentifier, acknowledgementOptions[dhcp4.OptionServerIdentifier])

	//packet.PadToMinSize()
	return packet
}

/*
 * Lets do a Full DHCP Request.
 */
func (this *Client) Request() (bool, dhcp4.Packet, error) {
	discoveryPacket, err := this.SendDiscoverPacket()
	if err != nil {
		return false, discoveryPacket, err
	}

	offerPacket, err := this.GetOffer(&discoveryPacket)
	if err != nil {
		return false, offerPacket, err
	}

	requestPacket, err := this.SendRequest(&offerPacket)
	if err != nil {
		return false, requestPacket, err
	}

	acknowledgement, err := this.GetAcknowledgement(&requestPacket)
	if err != nil {
		return false, acknowledgement, err
	}

	acknowledgementOptions := acknowledgement.ParseOptions()
	if dhcp4.MessageType(acknowledgementOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.ACK {
		return false, acknowledgement, nil
	}

	return true, acknowledgement, nil
}

/*
 * Renew a lease backed on the Acknowledgement Packet.
 * Returns Sucessfull, The AcknoledgementPacket, Any Errors
 */
func (this *Client) Renew(acknowledgement dhcp4.Packet) (bool, dhcp4.Packet, error) {
	renewRequest := this.RenewalRequestPacket(&acknowledgement)
	renewRequest.PadToMinSize()

	err := this.SendPacket(renewRequest)
	if err != nil {
		return false, renewRequest, err
	}

	newAcknowledgement, err := this.GetAcknowledgement(&acknowledgement)
	if err != nil {
		return false, newAcknowledgement, err
	}

	newAcknowledgementOptions := newAcknowledgement.ParseOptions()
	if dhcp4.MessageType(newAcknowledgementOptions[dhcp4.OptionDHCPMessageType][0]) != dhcp4.ACK {
		return false, newAcknowledgement, nil
	}

	return true, newAcknowledgement, nil
}
