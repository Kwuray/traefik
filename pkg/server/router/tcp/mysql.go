package tcp

import (
	"bufio"
	"net"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

const (
	MYSQL_PORT = "3306"
	MYSQL_INITIAL_PACKET_MAX_SIZE = 512
	MYSQL_CLIENT_SSL_REQUEST_MAX_PACKET_SIZE = 32
)

// isMySQL determines if the query is intended for MySQL.
//
// We cannot know this by analysing the contents of the buffer.
// Instead we check according to the port number 3306
func isMySQL(conn tcp.WriteCloser) (bool, error) {
	log.Error().Err(nil).Msg("Checking if it is MySQL... Port ?")
	log.Error().Err(nil).Msg(conn.LocalAddr().String())
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if (err != nil) {
		log.Error().Err(err).Msg("Can't parse host port.")
		return false, err
	}
	return port == MYSQL_PORT, nil
}

// This function connect to the mysql server to obtain the 'Protocol::HandshakeV10' packer.
//
// return the packet, the packet's size and error if any.
func getInitialHandshake() ([]byte, int, error) {
	conn, err := net.Dial("tcp", "172.28.0.3:3306")
	if err != nil {
		log.Error().Err(err).Msg("Can't connect mysql server.")
		return nil, 0, err
	}
	br := bufio.NewReader(conn)
	b := make([]byte, MYSQL_INITIAL_PACKET_MAX_SIZE)
	packetSize, err := br.Read(b)
	if err != nil {
		conn.Close()
		log.Error().Err(err).Msg("Can't read initial handshake packet from mysql server.")
		return nil, 0, err
	}
	return b, packetSize, nil
}

// Check if the mysql client did request SSL communication
func doesClientRequestSSL(data []byte, dataSize int) (bool) {
	packetInfoSize := 4
	clientFlagSize := 4 
	if (dataSize < packetInfoSize + clientFlagSize) {
		return false
	}
	//SSL Capabalities flag is the 12th bit of the 4 clientFlag's bytes, so the 4th bit of second clientFlag's bytes
	//See: https://dev.mysql.com/doc/dev/mysql-server/latest/group__group__cs__capabilities__flags.html
	mask := uint8(1 << 3)
	return (data[packetInfoSize + 1] & mask) == mask
}

func (R *Router) serveMySQL(conn tcp.WriteCloser) {
	initialHandshake, packetSize, err := getInitialHandshake()
	if err != nil {
		conn.Close()
		return
	}
	_, err = conn.Write(initialHandshake[0:packetSize])
	if err != nil {
		conn.Close()
		return
	}
	//Try to read RequestSSL packet
	b := make([]byte, MYSQL_CLIENT_SSL_REQUEST_MAX_PACKET_SIZE)
	br := bufio.NewReader(conn)
	packetSize, err = br.Read(b)
	if err != nil {
		conn.Close()
		return
	}
	if (!doesClientRequestSSL(b, packetSize)) {
		log.Error().Msg("MySQL client did not request SSL, we can't properly route this connection.")
		conn.Close();
		return
	}
	
	log.Error().Err(nil).Msg("MySQL success :DDD")
	conn.Close();
	return
}
