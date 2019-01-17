package main

import "strings"

// AnddosState keep overall server status and list of clients
type AnddosState struct {
	Level     int //(0)Normal, (10)Attack, (100)Overload; not used yet
	Threshold int
	//clients   map[string]AnddosClient
	AvgClient            AnddosClient
	RequestsCount        int64
	BlockedRequestsCount int64
	//StartedAt Time
}

// AnddosClient keeps information about a client
type AnddosClient struct {
	// missing: set, key
	ip string
	ua string

	RequestsCount int
	NotModCount   int
	HTTP1Count    int
	HTTP2Count    int
	HTTP3Count    int
	HTTP4Count    int
	HTTP5Count    int

	HTTPGetCount  int
	HTTPPostCount int

	AvgTime     float32
	AvgHTMLTime float32

	HTMLCount      int
	CSSCount       int
	JavasriptCount int
	ImageCount     int
	OtherCount     int
	// json etc.?

	HTTPCodeScore int
	MimeTypeScore int
	TimeScore     int
	PassSeqScore  int
	Score         int

	PassSeq []byte

	// Created at
	// FirstRequestAt Time
	// LastRequestAt Time
}

// AddRequest adds new requests information to its client
func (c *AnddosClient) AddRequest(HTTPCode int, HTTPMethod string, MimeType string, Time float32, Path string) {
	c.RequestsCount++

	// NotModCount
	if HTTPCode == 304 {
		c.NotModCount++
	}

	// HTTPCode
	if HTTPCode < 200 {
		c.HTTP1Count++
	} else if HTTPCode < 300 {
		c.HTTP2Count++
	} else if HTTPCode < 400 {
		c.HTTP3Count++
	} else if HTTPCode < 500 {
		c.HTTP4Count++
	} else {
		c.HTTP5Count++
	}

	// HTTPMethod
	switch HTTPMethod {
	case "GET":
		c.HTTPGetCount++
	case "POST":
		c.HTTPPostCount++
	}

	// MimeType TODO
	if strings.Contains(MimeType, "html") {
		c.HTMLCount++
	} else if strings.Contains(MimeType, "image") {
		c.ImageCount++
	} else if strings.Contains(MimeType, "javascript") {
		c.JavasriptCount++
	} else if strings.Contains(MimeType, "css") {
		c.CSSCount++
	} else {
		c.OtherCount++
	}

	// Time
	c.AvgTime = (c.AvgTime*float32(c.RequestsCount-1) + Time) / float32(c.RequestsCount)

	// PassSeq
	// c.PassSeq[length(c.PassSeq)] =
}
