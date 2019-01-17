package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"
)

// AnddosHandler passes HTTP connections via Reverse Proxy
func AnddosHandler(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method)
		log.Println(r.URL)
		timeStart := time.Now()
		remoteIP, _, _ := net.SplitHostPort(r.RemoteAddr)

		log.Println(r.RemoteAddr)
		// find or init a client
		if AnddosClients[remoteIP] == nil {
			AnddosClients[remoteIP] = &AnddosClient{}
		}

		// decide if block or serve
		if AnddosClients[remoteIP].Score >= AnddosStatus.Threshold {
			// blocked TODO
		} else {
			// Serve the request
			p.ServeHTTP(w, r)

			// update client stats
			AnddosClients[remoteIP].AddRequest(200, r.Method, w.Header().Get("Content-type"), float32(time.Since(timeStart))/1000, r.RequestURI)

			// TODO: print less often later..
			log.Printf("%+v\n", AnddosStatus)
			clientsDump, _ := json.Marshal(AnddosClients)
			ioutil.WriteFile("/tmp/anddos_clients_dump.json", clientsDump, 0600)

			//log.Println(w.Header().Get("Content-length")) add to scoring?
		}
	}
}
