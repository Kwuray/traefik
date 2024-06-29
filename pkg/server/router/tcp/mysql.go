package tcp

import (
	"net"

	"github.com/rs/zerolog/log"
	"github.com/traefik/traefik/v3/pkg/tcp"
)

const MYSQL_PORT = "3306"

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
