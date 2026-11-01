// Caddy built from source for the SlowShield edge image: the same main package as upstream's
// cmd/caddy (and xcaddy), with the standard modules only. See containers/caddy/Dockerfile.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// plug in Caddy modules here
	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() {
	caddycmd.Main()
}
