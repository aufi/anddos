package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// AnddosStatus keeps global status
var AnddosStatus AnddosState

// AnddosClients keeps list of all known clients based on IP
var AnddosClients map[string]*AnddosClient

func main() {
	// Parse CLI arguments
	var listenPort = flag.String("listenPort", ":8080", "Port where ANDDOS should listen")
	var upstreamURL = flag.String("upstreamURL", "http://localhost:80", "URL to protected server")
	flag.Parse()

	log.Println("Starting ANDDOS...")

	// Bootstrap Anddos
	AnddosStatus.Threshold = 1000
	AnddosClients = make(map[string]*AnddosClient)

	// Setup reverse proxy
	remote, err := url.Parse(*upstreamURL)
	if err != nil {
		panic(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(remote)
	http.HandleFunc("/", AnddosHandler(proxy))

	// Serve the traffic
	err = http.ListenAndServe(*listenPort, nil)
	if err != nil {
		panic(err)
	}
}
