package tcp

import (
	"bufio"
	"net"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

const (
	MYSQL_PORT = "3306"
	MYSQL_MAX_PACKET_SIZE = 512
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

func getInitialHandshake() ([]byte, int, error) {
	conn, err := net.Dial("tcp", "172.28.0.3:3306")
	if err != nil {
		log.Error().Err(err).Msg("Can't connect mysql server.")
		return nil, 0, err
	}
	br := bufio.NewReader(conn)
	b := make([]byte, MYSQL_MAX_PACKET_SIZE)
	packetSize, err := br.Read(b)
	if err != nil {
		conn.Close()
		log.Error().Err(err).Msg("Can't read initial handshake packet from mysql server.")
		return nil, 0, err
	}
	return b, packetSize, nil
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
	log.Error().Err(err).Msg("MySQL success :DDD")
	return
}
