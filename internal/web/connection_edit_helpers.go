package web

import "github.com/trilitech/Sieve/internal/connections"

// connWrapper adapts a *connections.Connection to the connectionGetter
// interface used by the connection-edit handlers. The interface lets us
// unit-test the handlers without requiring a live connections.Service.
type connWrapper struct{ c *connections.Connection }

func wrapConn(c *connections.Connection) connWrapper          { return connWrapper{c} }
func (w connWrapper) GetID() string                            { return w.c.ID }
func (w connWrapper) GetDisplayName() string                   { return w.c.DisplayName }
func (w connWrapper) GetConnectorType() string                 { return w.c.ConnectorType }
func (w connWrapper) GetConfig() map[string]any                { return w.c.Config }
