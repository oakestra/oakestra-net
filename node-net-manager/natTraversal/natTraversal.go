package natTraversal

import (
	"NetManager/logger"
	"NetManager/model"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun"
	"github.com/quic-go/quic-go"
)

var stunServers = []string{
	"stun:stun.l.google.com:19302",
	//"stun:stun.cloudflare.com:3478",
	//"stun:stun.stunprotocol.org:3478",
}

var responseChannel chan<- *quic.Conn

// getNATHoststring returns the public ip and port by querying a STUN server
func getNATHoststring() (string, error) {
	for _, stunServer := range stunServers {
		logger.DebugLogger().Println("Getting public host string from STUN server", stunServer)
		uri, err := stun.ParseURI(stunServer)
		if err != nil {
			logger.DebugLogger().Printf("Unable to parse stun server %v: %v", stunServer, err)
			continue
		}

		conn, err := stun.DialURI(uri, &stun.DialConfig{})
		if err != nil {
			logger.DebugLogger().Printf("Unable to connect to stun server %v: %v", stunServer, err)
			continue
		}

		done := make(chan struct{})
		var ip net.IP
		var port int
		var ConnErr error

		message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

		err = conn.Do(message, func(res stun.Event) {
			defer close(done)
			if res.Error != nil {
				ConnErr = res.Error
				return
			}
			var xorAddr stun.XORMappedAddress
			if err := xorAddr.GetFrom(res.Message); err != nil {
				ConnErr = err
				return
			}
			ip = xorAddr.IP
			port = xorAddr.Port
		})
		if err != nil {
			logger.DebugLogger().Printf("Unable to send stun request to %v: %v", stunServer, err)
			continue
		}

		// Wait for callback or timeout
		select {
		case <-done:
			if ConnErr != nil {
				logger.DebugLogger().Printf("STUN error from %v: %v", stunServer, ConnErr)
				continue
			}
			return fmt.Sprintf("%s:%d", ip, port), nil
		case <-time.After(5 * time.Second):
			logger.DebugLogger().Printf("Timeout waiting for response from %v", stunServer)
			continue
		}
	}
	return "", errors.New("unable to find public host")
}

// ConnectOverNAT will retry connecting to the passed nat multiple times.
// On success, it will write the established quic connection to responseChannel
func ConnectOverNAT(natHoststring string) {
	logger.DebugLogger().Printf("Attempting to connect over NAT to %s", natHoststring)
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-proxy"},
	}

	quicConf := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       30 * time.Second,
		EnableDatagrams:      true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var conn *quic.Conn
	var err error

	// repeat up to 5 times with small delay between attempts
	for i := 0; i < 5; i++ {
		conn, err = quic.DialAddr(ctx, natHoststring, tlsConf, quicConf)
		if err == nil {
			logger.DebugLogger().Println("Nat traversal succeeded")
			if responseChannel == nil {
				return
			}
			responseChannel <- conn
		}
		logger.DebugLogger().Println("Nat traversal failed:", err)
		time.Sleep(500 * time.Millisecond)
	}

}

// InitiateNATTraversal will resolve this workers NAT address via STUN, pass it to the cluster service manager
// and wait for the other workers NAT address to be resolved. Bother workers will then attempt to connect to each other
func InitiateNATTraversal(dstHoststring string, responseChan chan<- *quic.Conn, oid string, mqttRequestor func(src string, dst string, oid string) error) error {
	// find nat address
	src, err := getNATHoststring()
	if err != nil {
		logger.ErrorLogger().Printf("Unable to determine public hoststring: %v. Using public ip", err)

		ip := net.ParseIP(model.NetConfig.NodePublicAddress)
		if ip.To4() == nil {
			src = fmt.Sprintf("[%s]:%s", ip, model.NetConfig.NodePublicPort)
		} else {
			src = fmt.Sprintf("%s:%s", ip, model.NetConfig.NodePublicPort)
		}
	}

	logger.DebugLogger().Printf("Found public hoststring: %s", src)

	// send to cluster service manager
	err = mqttRequestor(src, dstHoststring, oid)
	if err != nil {
		logger.ErrorLogger().Println("Unable to request nat traversal:", err)
		return err
	}

	responseChannel = responseChan

	return nil
}
