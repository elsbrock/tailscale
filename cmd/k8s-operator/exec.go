// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	"tailscale.com/client/tailscale/apitype"
	tskube "tailscale.com/kube"
	"tailscale.com/ssh/tailssh"
	"tailscale.com/tailcfg"
	"tailscale.com/tstime"
	"tailscale.com/util/multierr"
)

// This file contains functionality related to forwarding 'kubectl exec' over
// the API server proxy, mostly this is the logic for recording 'kubectl exec'
// sessions and sending the recording to a tsrecorder instance.

const (
	SYN_STREAM ControlFrameType = 1 // https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.1
	SYN_REPLY  ControlFrameType = 2 // https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.2
	SYN_PING   ControlFrameType = 6 // https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.5
)

// Type of an SPDY control frame.
type ControlFrameType uint16

// setupRecording attempts to connect to the recorder specified in recOpts.
// Returns conn from provided opts, wrapped in recording logic. If connecting to
// the recorder fails or an error is received during the session and
// recOpts.failOpen is false, connection will be closed.
func (h *spdyHijacker) setupRecording(opts recOpts) (net.Conn, error) {
	const (
		// https://docs.asciinema.org/manual/asciicast/v2/
		asciicastv2 = 2
	)
	var wc io.WriteCloser
	h.log.Infof("kubectl exec session will be recorded, recorders: %v, fail open policy: %t", opts.recorderAddrs, opts.failOpen)
	ctx := context.Background()
	rw, _, errChan, err := tailssh.ConnectToRecorder(ctx, opts.recorderAddrs, h.s.Dialer())
	if err != nil {
		msg := fmt.Sprintf("error connecting to session recorders: %v", err)
		if !opts.failOpen {
			msg = msg + "failure mode is set to 'fail closed'; closing connection"
			resp := sessionForbiddenResp(msg)
			resp.Write(opts.conn)
			if err := opts.conn.Close(); err != nil {
				return nil, multierr.New(errors.New(msg), err)
			}
			return nil, errors.New(msg)
		} else {
			msg = msg + "failure mode is set to 'fail open'; continuing session without recording"
			h.log.Warnf(msg)
			return opts.conn, nil
		}
	} else {
		// TODO (irbekrm): log which recorder
		h.log.Info("successfully connected to a session recorder")
		wc = rw
	}
	go func() {
		err := <-errChan
		if err == nil {
			h.log.Info("finished uploading the recording")
			return
		}
		msg := fmt.Sprintf("connection to the session recorder errorred: %v;  failure mode set to 'fail closed'; closing connection", err)
		h.log.Error(msg)
		resp := sessionForbiddenResp(msg)
		resp.Write(opts.conn)
		if err := opts.conn.Close(); err != nil {
			h.log.Warnf("error closing connection: %v", err)
			return
		}
	}()
	cl := tstime.DefaultClock{}
	lc := &spdyRemoteConnRecorder{
		log:  h.log,
		Conn: opts.conn,
		lw: &loggingWriter{
			start:           cl.Now(),
			clock:           cl,
			failOpen:        opts.failOpen,
			sessionRecorder: wc,
			log:             h.log,
		},
	}

	qp := h.req.URL.Query()
	ch := CastHeader{
		Version:     asciicastv2,
		Timestamp:   lc.lw.start.Unix(),
		ExecCommand: strings.Join(qp["command"], " "),
		SrcNode:     strings.TrimSuffix(h.who.Node.Name, "."),
		SrcNodeID:   h.who.Node.StableID,
		Namespace:   opts.ns,
		Pod:         opts.pod,
	}
	if !h.who.Node.IsTagged() {
		ch.SrcNodeUser = h.who.UserProfile.LoginName
		ch.SrcNodeUserID = h.who.Node.User
	} else {
		ch.SrcNodeTags = h.who.Node.Tags
	}
	lc.ch = ch
	return lc, nil
}

// spdyRemoteConnRecorder is a wrapper around net.Conn. It reads the bytestream
// for a 'kubectl exec' session, sends session recording data to the configured
// recorder and forwards the raw bytes to the original destination.
type spdyRemoteConnRecorder struct {
	net.Conn
	// lw knows how to send data written to it to the session recorder.
	lw *loggingWriter
	ch CastHeader

	stdoutStreamID atomic.Uint32
	stderrStreamID atomic.Uint32
	resizeStreamID atomic.Uint32

	wmu    sync.Mutex // sequences writes
	closed bool

	rmu                 sync.Mutex // sequences reads
	writeCastHeaderOnce sync.Once

	zlibReqReader zlibReader
	// writeBuf is used to store data written to the connection that has not
	// yet been parsed as SPDY frames.
	writeBuf bytes.Buffer
	// readBuf is used to store data read from the connection that has not
	// yet been parsed as SPDY frames.
	readBuf bytes.Buffer
	log     *zap.SugaredLogger
}

// Reads parses bytes passed to it as SPDY frames and, frame by frame, passes
// them to the original destination. If the frame is a SPDY data frame for
// resize stream, also sends its payload to the session recorder.
func (c *spdyRemoteConnRecorder) Read(b []byte) (int, error) {
	log := c.log.With("spdyRemoteConnRecorder", "read")
	c.rmu.Lock()
	defer c.rmu.Unlock()
	n, err := c.Conn.Read(b)
	if err != nil {
		return n, err
	}
	c.readBuf.Write(b[:n])

	var sf spdyFrame
	ok, err := sf.Parse(c.readBuf.Bytes(), log)
	if err != nil {
		return 0, fmt.Errorf("error parsing data read from connection: %w", err)
	}
	if !ok {
		// The parsed data in the buffer will be processed together with
		// the new data on the next call to Read.
		return n, nil
	}
	c.readBuf.Next(len(sf.Raw)) // advance buffer past the parsed frame

	if !sf.Ctrl { // data frame
		switch sf.StreamID {
		case c.resizeStreamID.Load():
			var err error
			c.writeCastHeaderOnce.Do(func() {
				var resizeMsg struct {
					Width  int `json:"width"`
					Height int `json:"height"`
				}
				if err = json.Unmarshal(sf.Payload, &resizeMsg); err != nil {
					return
				}
				c.ch.Width = resizeMsg.Width
				c.ch.Height = resizeMsg.Height
				var j []byte
				j, err = json.Marshal(c.ch)
				if err != nil {
					return
				}
				j = append(j, '\n')
				_, err = c.lw.sessionRecorder.Write(j)
				if err != nil {
					c.log.Debugf("received error from recorder: %v", err)
				}
			})
			if err != nil {
				return 0, err
			}
		}
		return n, nil
	}
	// We always want to parse the headers, even if we don't care about the
	// frame, as we need to advance the zlib reader otherwise we will get
	// garbage.
	header, err := sf.parseHeaders(&c.zlibReqReader, log)
	if err != nil {
		return 0, fmt.Errorf("error parsing frame headers: %w", err)
	}
	if sf.Type == SYN_STREAM {
		c.storeStreamID(sf, header)
	}
	return n, nil
}

// Write forwards the raw data of the latest parsed SPDY frame to the original
// destination. If the frame is an SPDY data frame, it also sends the payload to
// the connected session recorder.
func (c *spdyRemoteConnRecorder) Write(b []byte) (int, error) {
	log := c.log.With("spdyRemoteConnRecorder", "write")
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.writeBuf.Write(b)

	var sf spdyFrame
	ok, err := sf.Parse(c.writeBuf.Bytes(), log)
	if err != nil {
		return 0, fmt.Errorf("error parsing data: %w", err)
	}
	if !ok {
		// The parsed data in the buffer will be processed together with
		// the new data on the next call to Write.
		return len(b), nil
	}
	c.writeBuf.Next(len(sf.Raw)) // advance buffer past the parsed frame

	// If this is a stdout or stderr data frame, send its payload to the
	// session recorder.
	if !sf.Ctrl {
		switch sf.StreamID {
		case c.stdoutStreamID.Load(), c.stderrStreamID.Load():
			if _, err := c.lw.Write(sf.Payload); err != nil {
				return 0, fmt.Errorf("error sending payload to session recorder: %w", err)
			}
		}
	}
	// Forward the whole frame to the original destination.
	_, err = c.Conn.Write(sf.Raw) // send to net.Conn
	return len(b), err
}

func (c *spdyRemoteConnRecorder) Close() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.closed {
		return nil
	}
	if c.writeBuf.Len() > 0 {
		c.Conn.Write(c.writeBuf.Bytes())
	}
	c.writeBuf.Reset()
	c.closed = true
	err := c.Conn.Close()
	c.lw.Close()
	return err
}

// loggingWriter knows how to send the provided bytes to the configured session
// recorder in asciinema format.
type loggingWriter struct {
	start time.Time
	clock tstime.Clock

	// failOpen specifies whether the session should be allowed to
	// continue if writing to the recording fails.
	failOpen bool

	// recordingFailedOpen specifies whether we've failed to write to
	// r.out and should stop trying. It is set to true if we fail to write
	// to r.out and r.failOpen is set.
	recordingFailedOpen bool
	log                 *zap.SugaredLogger

	mu              sync.Mutex // guards writes to sessionRecorder
	sessionRecorder io.WriteCloser
}

// Write appends timestamp to the provided bytes and sends them to the
// configured session recorder.
func (w *loggingWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	if w.recordingFailedOpen {
		return 0, nil
	}
	j, err := json.Marshal([]any{
		w.clock.Now().Sub(w.start).Seconds(),
		"o",
		string(p),
	})
	if err != nil {
		return 0, fmt.Errorf("error marhalling payload: %w", err)
	}
	j = append(j, '\n')
	if err := w.writeCastLine(j); err != nil {
		if !w.failOpen {
			return 0, fmt.Errorf("error writing payload to recorder: %w", err)
		}
		w.recordingFailedOpen = true
	}
	return len(p), nil
}

func (w *loggingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sessionRecorder == nil {
		return nil
	}
	err := w.sessionRecorder.Close()
	w.sessionRecorder = nil
	return err
}

// writeCastLine sends bytes to the session recorder. The bytes should be in
// asciinema format.
func (w *loggingWriter) writeCastLine(j []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.sessionRecorder == nil {
		return errors.New("logger closed")
	}
	_, err := w.sessionRecorder.Write(j)
	if err != nil {
		return fmt.Errorf("logger write error: %w", err)
	}
	return nil
}

// spdyFrame is a parsed SPDY frame as defined in
// https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt
// A SPDY frame can be either a control frame or a data frame.
type spdyFrame struct {
	Raw []byte // full frame as raw bytes

	// Common frame fields:
	Ctrl    bool   // true if this is a SPDY control frame
	Payload []byte // payload as raw bytes

	// Control frame fields:
	Version uint16 // SPDY protocol version
	Type    ControlFrameType

	// Data frame fields:
	// StreamID is the id of the steam to which this data frame belongs.
	// SPDY allows transmitting multiple data streams concurrently.
	StreamID uint32
}

// Parse parses bytes into spdyFrame.
// If the bytes don't contain a full frame, return false.
//
// Control frame structure:
//
//	 +----------------------------------+
//	|C| Version(15bits) | Type(16bits) |
//	+----------------------------------+
//	| Flags (8)  |  Length (24 bits)   |
//	+----------------------------------+
//	|               Data               |
//	+----------------------------------+
//
// Data frame structure:
//
//	+----------------------------------+
//	|C|       Stream-ID (31bits)       |
//	+----------------------------------+
//	| Flags (8)  |  Length (24 bits)   |
//	+----------------------------------+
//	|               Data               |
//	+----------------------------------+
//
// https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt
func (sf *spdyFrame) Parse(b []byte, log *zap.SugaredLogger) (ok bool, _ error) {
	const (
		spdyHeaderLength = 8
	)
	have := len(b)
	if have < spdyHeaderLength { // input does not contain full frame
		return false, nil
	}

	if !isSPDYFrameHeader(b) {
		return false, fmt.Errorf("bytes %v do not seem to contain SPDY frames. Ensure that you are using a SPDY based client to 'kubectl exec'.", b)
	}

	payloadLength := readInt24(b[5:8])
	frameLength := payloadLength + spdyHeaderLength
	if have < frameLength { // input does not contain full frame
		return false, nil
	}

	frame := b[:frameLength:frameLength] // enforce frameLength capacity

	sf.Raw = frame
	sf.Payload = frame[spdyHeaderLength:frameLength]

	sf.Ctrl = hasControlBitSet(frame)

	if !sf.Ctrl { // data frame
		sf.StreamID = dataFrameStreamID(frame)
		return true, nil
	}

	sf.Version = controlFrameVersion(frame)
	sf.Type = controlFrameType(frame)
	return true, nil
}

// parseHeaders retrieves any headers from this spdyFrame.
func (sf *spdyFrame) parseHeaders(z *zlibReader, log *zap.SugaredLogger) (http.Header, error) {
	if !sf.Ctrl {
		return nil, fmt.Errorf("[unexpected] parseHeaders called for a frame that is not a control frame")
	}
	const (
		// +------------------------------------+
		// |X|           Stream-ID (31bits)     |
		// +------------------------------------+
		// |X| Associated-To-Stream-ID (31bits) |
		// +------------------------------------+
		// | Pri|Unused | Slot |                |
		// +-------------------+                |
		synStreamPayloadLengthBeforeHeaders = 10

		// +------------------------------------+
		// |X|           Stream-ID (31bits)     |
		//+------------------------------------+
		synReplyPayloadLengthBeforeHeaders = 4

		// +----------------------------------|
		// |            32-bit ID             |
		// +----------------------------------+
		pingPayloadLength = 4
	)

	switch sf.Type {
	case SYN_STREAM:
		if len(sf.Payload) < synStreamPayloadLengthBeforeHeaders {
			return nil, fmt.Errorf("SYN_STREAM frame too short: %v", len(sf.Payload))
		}
		z.Set(sf.Payload[synStreamPayloadLengthBeforeHeaders:])
		return parseHeaders(z, log)
	case SYN_REPLY:
		if len(sf.Payload) < synReplyPayloadLengthBeforeHeaders {
			return nil, fmt.Errorf("SYN_REPLY frame too short: %v", len(sf.Payload))
		}
		if len(sf.Payload) == synReplyPayloadLengthBeforeHeaders {
			return nil, nil // no headers
		}
		z.Set(sf.Payload[synReplyPayloadLengthBeforeHeaders:])
		return parseHeaders(z, log)
	case SYN_PING:
		if len(sf.Payload) != pingPayloadLength {
			return nil, fmt.Errorf("PING frame with unexpected length %v", len(sf.Payload))
		}
		return nil, nil // ping frame has no headers

	default:
		log.Infof("[unexpected] unknown control frame type %v", sf.Type)
	}
	return nil, nil
}

// zlibReader contains functionality to parse zlib compressed SPDY data.
// See https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.10.1
type zlibReader struct {
	io.ReadCloser
	underlying io.LimitedReader // zlib compressed SPDY data
}

// Read decompresses zlibReader's underlying zlib compressed SPDY data and reads
// it into b.
func (z *zlibReader) Read(b []byte) (int, error) {
	if z.ReadCloser == nil {
		r, err := zlib.NewReaderDict(&z.underlying, []byte(spdyTxtDictionary))
		if err != nil {
			return 0, err
		}
		z.ReadCloser = r
	}
	return z.ReadCloser.Read(b)
}

// Set sets zlibReader's underlying data. b must be zlib compressed SPDY data.
func (z *zlibReader) Set(b []byte) {
	z.underlying.R = bytes.NewReader(b)
	z.underlying.N = int64(len(b))
}

// parseHeaders expects to be passed a reader that contains a compressed SPDY control
// frame Name/Value Header Block with 0 or more headers:
//
// | Number of Name/Value pairs (int32) |   <+
// +------------------------------------+    |
// |     Length of name (int32)         |    | This section is the "Name/Value
// +------------------------------------+    | Header Block", and is compressed.
// |           Name (string)            |    |
// +------------------------------------+    |
// |     Length of value  (int32)       |    |
// +------------------------------------+    |
// |          Value   (string)          |    |
// +------------------------------------+    |
// |           (repeats)                |   <+
//
// It extracts the headers and returns them as http.Header. By doing that it
// also advances the provided reader past the headers block.
// See also https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.10
func parseHeaders(decompressor io.Reader, log *zap.SugaredLogger) (http.Header, error) {
	buf := bufPool.Get().(*bytes.Buffer)
	defer bufPool.Put(buf)
	buf.Reset()

	// readUint32 reads the next 4 decompressed bytes from the decompressor
	// as a uint32.
	readUint32 := func() (uint32, error) {
		const uint32Length = 4
		if _, err := io.CopyN(buf, decompressor, uint32Length); err != nil { // decompress
			return 0, fmt.Errorf("error decompressing bytes: %w", err)
		}
		return binary.BigEndian.Uint32(buf.Next(uint32Length)), nil // return as uint32
	}

	// readLenBytes decompresses and returns as bytes the next 'Name' or 'Value'
	// field from SPDY Name/Value header block. decompressor must be at
	// 'Length of name'/'Length of value' field.
	readLenBytes := func() ([]byte, error) {
		xLen, err := readUint32() // length of field to read
		if err != nil {
			return nil, err
		}
		if _, err := io.CopyN(buf, decompressor, int64(xLen)); err != nil { // decompress
			return nil, err
		}
		return buf.Next(int(xLen)), nil
	}

	numHeaders, err := readUint32()
	if err != nil {
		return nil, fmt.Errorf("error determining num headers: %v", err)
	}
	h := make(http.Header, numHeaders)
	for i := uint32(0); i < numHeaders; i++ {
		name, err := readLenBytes()
		if err != nil {
			return nil, err
		}
		ns := string(name)
		if _, ok := h[ns]; ok {
			return nil, fmt.Errorf("invalid data: duplicate header %q", ns)
		}
		val, err := readLenBytes()
		if err != nil {
			return nil, fmt.Errorf("error reading header data: %w", err)
		}
		for _, v := range bytes.Split(val, headerSep) {
			h.Add(ns, string(v))
		}
	}
	return h, nil
}

// determineRecorderConfig determines recorder config from requester's peer
// capabilities. Determines whether a 'kubectl exec' session from this requester
// needs to be recorded and what recorders the recording should be sent to.
func determineRecorderConfig(who *apitype.WhoIsResponse) (failOpen bool, recorderAddresses []netip.AddrPort, _ error) {
	if who == nil {
		return false, nil, errors.New("[unexpected] cannot determine caller")
	}
	failOpen = true
	rules, err := tailcfg.UnmarshalCapJSON[tskube.KubernetesCapRule](who.CapMap, tailcfg.PeerCapabilityKubernetes)
	if err != nil {
		return failOpen, nil, fmt.Errorf("failed to unmarshal Kubernetes capability: %w", err)
	}
	if len(rules) == 0 {
		return failOpen, nil, nil
	}

	for _, rule := range rules {
		if len(rule.RecorderAddrs) != 0 {
			// TODO (irbekrm): here or later determine if the
			// recorders behind those addrs are online - else we
			// spend 30s trying to reach a recorder whose tailscale
			// status is offline.
			recorderAddresses = append(recorderAddresses, rule.RecorderAddrs...)
		}
		if rule.EnforceRecorder {
			failOpen = false
		}
	}
	return failOpen, recorderAddresses, nil
}

// parseSynStream parses SYN_STREAM SPDY control frame and updates
// spdyRemoteConnRecorder to store the newly created stream's ID if it is one of
// the stream types we care about. Storing stream_id:stream_type mapping allows
// us to parse received data frames (that have stream IDs) differently depening
// on which stream they belong to (i.e send data frame payload for stdout stream
// to session recorder).
func (c *spdyRemoteConnRecorder) storeStreamID(sf spdyFrame, header http.Header) {
	const (
		streamTypeHeaderKey = "Streamtype"
	)
	id := binary.BigEndian.Uint32(sf.Payload[0:4])
	switch header.Get(streamTypeHeaderKey) {
	case corev1.StreamTypeStdout:
		c.stdoutStreamID.Store(id)
	case corev1.StreamTypeStderr:
		c.stderrStreamID.Store(id)
	case corev1.StreamTypeResize:
		c.resizeStreamID.Store(id)
	}
}

// CastHeader is the asciicast header to be sent to the recorder at the start of
// the recording of a session.
// https://docs.asciinema.org/manual/asciicast/v2/#header
type CastHeader struct {
	// Version is the asciinema file format version.
	Version int `json:"version"`

	// Width is the terminal width in characters.
	Width int `json:"width"`

	// Height is the terminal height in characters.
	Height int `json:"height"`

	// Timestamp is the unix timestamp of when the recording started.
	Timestamp int64 `json:"timestamp"`

	// Tailscale-specific fields: SrcNode is the full MagicDNS name of the
	// tailnet node originating the connection, without the trailing dot.
	SrcNode string `json:"srcNode"`

	// SrcNodeID is the node ID of the tailnet node originating the connection.
	SrcNodeID tailcfg.StableNodeID `json:"srcNodeID"`

	// SrcNodeTags is the list of tags on the node originating the connection (if any).
	SrcNodeTags []string `json:"srcNodeTags,omitempty"`

	// SrcNodeUserID is the user ID of the node originating the connection (if not tagged).
	SrcNodeUserID tailcfg.UserID `json:"srcNodeUserID,omitempty"` // if not tagged

	// SrcNodeUser is the LoginName of the node originating the connection (if not tagged).
	SrcNodeUser string `json:"srcNodeUser,omitempty"`

	// Kubernetes-specific fields:
	// Namespace of the Pod that is being exec-ed to.
	Namespace string `json:"namespace,omitempty"`
	// Name of the Pod that is being exec-ed to.
	Pod string `json:"pod,omitempty"`
	// ExecCommand is the command passed to 'kubectl exec' i.e 'sh' in 'kubectl exec -it my-pod sh'.
	// Note that a Command field should not be used to store this info as
	// that will make tsrecorder consider that the session consists of a
	// non-interactive command.
	ExecCommand string
}

// spdyTxtDictionary is the dictionary defined in the SPDY spec.
// https://datatracker.ietf.org/doc/html/draft-mbelshe-httpbis-spdy-00#section-2.6.10.1
var spdyTxtDictionary = []byte{
	0x00, 0x00, 0x00, 0x07, 0x6f, 0x70, 0x74, 0x69, // - - - - o p t i
	0x6f, 0x6e, 0x73, 0x00, 0x00, 0x00, 0x04, 0x68, // o n s - - - - h
	0x65, 0x61, 0x64, 0x00, 0x00, 0x00, 0x04, 0x70, // e a d - - - - p
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x03, 0x70, // o s t - - - - p
	0x75, 0x74, 0x00, 0x00, 0x00, 0x06, 0x64, 0x65, // u t - - - - d e
	0x6c, 0x65, 0x74, 0x65, 0x00, 0x00, 0x00, 0x05, // l e t e - - - -
	0x74, 0x72, 0x61, 0x63, 0x65, 0x00, 0x00, 0x00, // t r a c e - - -
	0x06, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x00, // - a c c e p t -
	0x00, 0x00, 0x0e, 0x61, 0x63, 0x63, 0x65, 0x70, // - - - a c c e p
	0x74, 0x2d, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, // t - c h a r s e
	0x74, 0x00, 0x00, 0x00, 0x0f, 0x61, 0x63, 0x63, // t - - - - a c c
	0x65, 0x70, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f, // e p t - e n c o
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x0f, // d i n g - - - -
	0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x6c, // a c c e p t - l
	0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, 0x00, // a n g u a g e -
	0x00, 0x00, 0x0d, 0x61, 0x63, 0x63, 0x65, 0x70, // - - - a c c e p
	0x74, 0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x73, // t - r a n g e s
	0x00, 0x00, 0x00, 0x03, 0x61, 0x67, 0x65, 0x00, // - - - - a g e -
	0x00, 0x00, 0x05, 0x61, 0x6c, 0x6c, 0x6f, 0x77, // - - - a l l o w
	0x00, 0x00, 0x00, 0x0d, 0x61, 0x75, 0x74, 0x68, // - - - - a u t h
	0x6f, 0x72, 0x69, 0x7a, 0x61, 0x74, 0x69, 0x6f, // o r i z a t i o
	0x6e, 0x00, 0x00, 0x00, 0x0d, 0x63, 0x61, 0x63, // n - - - - c a c
	0x68, 0x65, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, // h e - c o n t r
	0x6f, 0x6c, 0x00, 0x00, 0x00, 0x0a, 0x63, 0x6f, // o l - - - - c o
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, // n n e c t i o n
	0x00, 0x00, 0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, // - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x62, 0x61, 0x73, 0x65, // e n t - b a s e
	0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, 0x6e, 0x74, // - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x65, 0x6e, 0x63, 0x6f, // e n t - e n c o
	0x64, 0x69, 0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, // d i n g - - - -
	0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, // c o n t e n t -
	0x6c, 0x61, 0x6e, 0x67, 0x75, 0x61, 0x67, 0x65, // l a n g u a g e
	0x00, 0x00, 0x00, 0x0e, 0x63, 0x6f, 0x6e, 0x74, // - - - - c o n t
	0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x65, 0x6e, 0x67, // e n t - l e n g
	0x74, 0x68, 0x00, 0x00, 0x00, 0x10, 0x63, 0x6f, // t h - - - - c o
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x6c, 0x6f, // n t e n t - l o
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, // c a t i o n - -
	0x00, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, // - - c o n t e n
	0x74, 0x2d, 0x6d, 0x64, 0x35, 0x00, 0x00, 0x00, // t - m d 5 - - -
	0x0d, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, // - c o n t e n t
	0x2d, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, // - r a n g e - -
	0x00, 0x0c, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, // - - c o n t e n
	0x74, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x00, 0x00, // t - t y p e - -
	0x00, 0x04, 0x64, 0x61, 0x74, 0x65, 0x00, 0x00, // - - d a t e - -
	0x00, 0x04, 0x65, 0x74, 0x61, 0x67, 0x00, 0x00, // - - e t a g - -
	0x00, 0x06, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, // - - e x p e c t
	0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x70, 0x69, // - - - - e x p i
	0x72, 0x65, 0x73, 0x00, 0x00, 0x00, 0x04, 0x66, // r e s - - - - f
	0x72, 0x6f, 0x6d, 0x00, 0x00, 0x00, 0x04, 0x68, // r o m - - - - h
	0x6f, 0x73, 0x74, 0x00, 0x00, 0x00, 0x08, 0x69, // o s t - - - - i
	0x66, 0x2d, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, // f - m a t c h -
	0x00, 0x00, 0x11, 0x69, 0x66, 0x2d, 0x6d, 0x6f, // - - - i f - m o
	0x64, 0x69, 0x66, 0x69, 0x65, 0x64, 0x2d, 0x73, // d i f i e d - s
	0x69, 0x6e, 0x63, 0x65, 0x00, 0x00, 0x00, 0x0d, // i n c e - - - -
	0x69, 0x66, 0x2d, 0x6e, 0x6f, 0x6e, 0x65, 0x2d, // i f - n o n e -
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x00, 0x00, 0x00, // m a t c h - - -
	0x08, 0x69, 0x66, 0x2d, 0x72, 0x61, 0x6e, 0x67, // - i f - r a n g
	0x65, 0x00, 0x00, 0x00, 0x13, 0x69, 0x66, 0x2d, // e - - - - i f -
	0x75, 0x6e, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, // u n m o d i f i
	0x65, 0x64, 0x2d, 0x73, 0x69, 0x6e, 0x63, 0x65, // e d - s i n c e
	0x00, 0x00, 0x00, 0x0d, 0x6c, 0x61, 0x73, 0x74, // - - - - l a s t
	0x2d, 0x6d, 0x6f, 0x64, 0x69, 0x66, 0x69, 0x65, // - m o d i f i e
	0x64, 0x00, 0x00, 0x00, 0x08, 0x6c, 0x6f, 0x63, // d - - - - l o c
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, // a t i o n - - -
	0x0c, 0x6d, 0x61, 0x78, 0x2d, 0x66, 0x6f, 0x72, // - m a x - f o r
	0x77, 0x61, 0x72, 0x64, 0x73, 0x00, 0x00, 0x00, // w a r d s - - -
	0x06, 0x70, 0x72, 0x61, 0x67, 0x6d, 0x61, 0x00, // - p r a g m a -
	0x00, 0x00, 0x12, 0x70, 0x72, 0x6f, 0x78, 0x79, // - - - p r o x y
	0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, // - a u t h e n t
	0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, 0x00, // i c a t e - - -
	0x13, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2d, 0x61, // - p r o x y - a
	0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x7a, 0x61, // u t h o r i z a
	0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x05, // t i o n - - - -
	0x72, 0x61, 0x6e, 0x67, 0x65, 0x00, 0x00, 0x00, // r a n g e - - -
	0x07, 0x72, 0x65, 0x66, 0x65, 0x72, 0x65, 0x72, // - r e f e r e r
	0x00, 0x00, 0x00, 0x0b, 0x72, 0x65, 0x74, 0x72, // - - - - r e t r
	0x79, 0x2d, 0x61, 0x66, 0x74, 0x65, 0x72, 0x00, // y - a f t e r -
	0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, // - - - s e r v e
	0x72, 0x00, 0x00, 0x00, 0x02, 0x74, 0x65, 0x00, // r - - - - t e -
	0x00, 0x00, 0x07, 0x74, 0x72, 0x61, 0x69, 0x6c, // - - - t r a i l
	0x65, 0x72, 0x00, 0x00, 0x00, 0x11, 0x74, 0x72, // e r - - - - t r
	0x61, 0x6e, 0x73, 0x66, 0x65, 0x72, 0x2d, 0x65, // a n s f e r - e
	0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00, // n c o d i n g -
	0x00, 0x00, 0x07, 0x75, 0x70, 0x67, 0x72, 0x61, // - - - u p g r a
	0x64, 0x65, 0x00, 0x00, 0x00, 0x0a, 0x75, 0x73, // d e - - - - u s
	0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, // e r - a g e n t
	0x00, 0x00, 0x00, 0x04, 0x76, 0x61, 0x72, 0x79, // - - - - v a r y
	0x00, 0x00, 0x00, 0x03, 0x76, 0x69, 0x61, 0x00, // - - - - v i a -
	0x00, 0x00, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69, // - - - w a r n i
	0x6e, 0x67, 0x00, 0x00, 0x00, 0x10, 0x77, 0x77, // n g - - - - w w
	0x77, 0x2d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, // w - a u t h e n
	0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x00, 0x00, // t i c a t e - -
	0x00, 0x06, 0x6d, 0x65, 0x74, 0x68, 0x6f, 0x64, // - - m e t h o d
	0x00, 0x00, 0x00, 0x03, 0x67, 0x65, 0x74, 0x00, // - - - - g e t -
	0x00, 0x00, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, // - - - s t a t u
	0x73, 0x00, 0x00, 0x00, 0x06, 0x32, 0x30, 0x30, // s - - - - 2 0 0
	0x20, 0x4f, 0x4b, 0x00, 0x00, 0x00, 0x07, 0x76, // - O K - - - - v
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00, 0x00, // e r s i o n - -
	0x00, 0x08, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, // - - H T T P - 1
	0x2e, 0x31, 0x00, 0x00, 0x00, 0x03, 0x75, 0x72, // - 1 - - - - u r
	0x6c, 0x00, 0x00, 0x00, 0x06, 0x70, 0x75, 0x62, // l - - - - p u b
	0x6c, 0x69, 0x63, 0x00, 0x00, 0x00, 0x0a, 0x73, // l i c - - - - s
	0x65, 0x74, 0x2d, 0x63, 0x6f, 0x6f, 0x6b, 0x69, // e t - c o o k i
	0x65, 0x00, 0x00, 0x00, 0x0a, 0x6b, 0x65, 0x65, // e - - - - k e e
	0x70, 0x2d, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x00, // p - a l i v e -
	0x00, 0x00, 0x06, 0x6f, 0x72, 0x69, 0x67, 0x69, // - - - o r i g i
	0x6e, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x32, // n 1 0 0 1 0 1 2
	0x30, 0x31, 0x32, 0x30, 0x32, 0x32, 0x30, 0x35, // 0 1 2 0 2 2 0 5
	0x32, 0x30, 0x36, 0x33, 0x30, 0x30, 0x33, 0x30, // 2 0 6 3 0 0 3 0
	0x32, 0x33, 0x30, 0x33, 0x33, 0x30, 0x34, 0x33, // 2 3 0 3 3 0 4 3
	0x30, 0x35, 0x33, 0x30, 0x36, 0x33, 0x30, 0x37, // 0 5 3 0 6 3 0 7
	0x34, 0x30, 0x32, 0x34, 0x30, 0x35, 0x34, 0x30, // 4 0 2 4 0 5 4 0
	0x36, 0x34, 0x30, 0x37, 0x34, 0x30, 0x38, 0x34, // 6 4 0 7 4 0 8 4
	0x30, 0x39, 0x34, 0x31, 0x30, 0x34, 0x31, 0x31, // 0 9 4 1 0 4 1 1
	0x34, 0x31, 0x32, 0x34, 0x31, 0x33, 0x34, 0x31, // 4 1 2 4 1 3 4 1
	0x34, 0x34, 0x31, 0x35, 0x34, 0x31, 0x36, 0x34, // 4 4 1 5 4 1 6 4
	0x31, 0x37, 0x35, 0x30, 0x32, 0x35, 0x30, 0x34, // 1 7 5 0 2 5 0 4
	0x35, 0x30, 0x35, 0x32, 0x30, 0x33, 0x20, 0x4e, // 5 0 5 2 0 3 - N
	0x6f, 0x6e, 0x2d, 0x41, 0x75, 0x74, 0x68, 0x6f, // o n - A u t h o
	0x72, 0x69, 0x74, 0x61, 0x74, 0x69, 0x76, 0x65, // r i t a t i v e
	0x20, 0x49, 0x6e, 0x66, 0x6f, 0x72, 0x6d, 0x61, // - I n f o r m a
	0x74, 0x69, 0x6f, 0x6e, 0x32, 0x30, 0x34, 0x20, // t i o n 2 0 4 -
	0x4e, 0x6f, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x65, // N o - C o n t e
	0x6e, 0x74, 0x33, 0x30, 0x31, 0x20, 0x4d, 0x6f, // n t 3 0 1 - M o
	0x76, 0x65, 0x64, 0x20, 0x50, 0x65, 0x72, 0x6d, // v e d - P e r m
	0x61, 0x6e, 0x65, 0x6e, 0x74, 0x6c, 0x79, 0x34, // a n e n t l y 4
	0x30, 0x30, 0x20, 0x42, 0x61, 0x64, 0x20, 0x52, // 0 0 - B a d - R
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x34, 0x30, // e q u e s t 4 0
	0x31, 0x20, 0x55, 0x6e, 0x61, 0x75, 0x74, 0x68, // 1 - U n a u t h
	0x6f, 0x72, 0x69, 0x7a, 0x65, 0x64, 0x34, 0x30, // o r i z e d 4 0
	0x33, 0x20, 0x46, 0x6f, 0x72, 0x62, 0x69, 0x64, // 3 - F o r b i d
	0x64, 0x65, 0x6e, 0x34, 0x30, 0x34, 0x20, 0x4e, // d e n 4 0 4 - N
	0x6f, 0x74, 0x20, 0x46, 0x6f, 0x75, 0x6e, 0x64, // o t - F o u n d
	0x35, 0x30, 0x30, 0x20, 0x49, 0x6e, 0x74, 0x65, // 5 0 0 - I n t e
	0x72, 0x6e, 0x61, 0x6c, 0x20, 0x53, 0x65, 0x72, // r n a l - S e r
	0x76, 0x65, 0x72, 0x20, 0x45, 0x72, 0x72, 0x6f, // v e r - E r r o
	0x72, 0x35, 0x30, 0x31, 0x20, 0x4e, 0x6f, 0x74, // r 5 0 1 - N o t
	0x20, 0x49, 0x6d, 0x70, 0x6c, 0x65, 0x6d, 0x65, // - I m p l e m e
	0x6e, 0x74, 0x65, 0x64, 0x35, 0x30, 0x33, 0x20, // n t e d 5 0 3 -
	0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x20, // S e r v i c e -
	0x55, 0x6e, 0x61, 0x76, 0x61, 0x69, 0x6c, 0x61, // U n a v a i l a
	0x62, 0x6c, 0x65, 0x4a, 0x61, 0x6e, 0x20, 0x46, // b l e J a n - F
	0x65, 0x62, 0x20, 0x4d, 0x61, 0x72, 0x20, 0x41, // e b - M a r - A
	0x70, 0x72, 0x20, 0x4d, 0x61, 0x79, 0x20, 0x4a, // p r - M a y - J
	0x75, 0x6e, 0x20, 0x4a, 0x75, 0x6c, 0x20, 0x41, // u n - J u l - A
	0x75, 0x67, 0x20, 0x53, 0x65, 0x70, 0x74, 0x20, // u g - S e p t -
	0x4f, 0x63, 0x74, 0x20, 0x4e, 0x6f, 0x76, 0x20, // O c t - N o v -
	0x44, 0x65, 0x63, 0x20, 0x30, 0x30, 0x3a, 0x30, // D e c - 0 0 - 0
	0x30, 0x3a, 0x30, 0x30, 0x20, 0x4d, 0x6f, 0x6e, // 0 - 0 0 - M o n
	0x2c, 0x20, 0x54, 0x75, 0x65, 0x2c, 0x20, 0x57, // - - T u e - - W
	0x65, 0x64, 0x2c, 0x20, 0x54, 0x68, 0x75, 0x2c, // e d - - T h u -
	0x20, 0x46, 0x72, 0x69, 0x2c, 0x20, 0x53, 0x61, // - F r i - - S a
	0x74, 0x2c, 0x20, 0x53, 0x75, 0x6e, 0x2c, 0x20, // t - - S u n - -
	0x47, 0x4d, 0x54, 0x63, 0x68, 0x75, 0x6e, 0x6b, // G M T c h u n k
	0x65, 0x64, 0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, // e d - t e x t -
	0x68, 0x74, 0x6d, 0x6c, 0x2c, 0x69, 0x6d, 0x61, // h t m l - i m a
	0x67, 0x65, 0x2f, 0x70, 0x6e, 0x67, 0x2c, 0x69, // g e - p n g - i
	0x6d, 0x61, 0x67, 0x65, 0x2f, 0x6a, 0x70, 0x67, // m a g e - j p g
	0x2c, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2f, 0x67, // - i m a g e - g
	0x69, 0x66, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, // i f - a p p l i
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, // c a t i o n - x
	0x6d, 0x6c, 0x2c, 0x61, 0x70, 0x70, 0x6c, 0x69, // m l - a p p l i
	0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x78, // c a t i o n - x
	0x68, 0x74, 0x6d, 0x6c, 0x2b, 0x78, 0x6d, 0x6c, // h t m l - x m l
	0x2c, 0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, // - t e x t - p l
	0x61, 0x69, 0x6e, 0x2c, 0x74, 0x65, 0x78, 0x74, // a i n - t e x t
	0x2f, 0x6a, 0x61, 0x76, 0x61, 0x73, 0x63, 0x72, // - j a v a s c r
	0x69, 0x70, 0x74, 0x2c, 0x70, 0x75, 0x62, 0x6c, // i p t - p u b l
	0x69, 0x63, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, // i c p r i v a t
	0x65, 0x6d, 0x61, 0x78, 0x2d, 0x61, 0x67, 0x65, // e m a x - a g e
	0x3d, 0x67, 0x7a, 0x69, 0x70, 0x2c, 0x64, 0x65, // - g z i p - d e
	0x66, 0x6c, 0x61, 0x74, 0x65, 0x2c, 0x73, 0x64, // f l a t e - s d
	0x63, 0x68, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, // c h c h a r s e
	0x74, 0x3d, 0x75, 0x74, 0x66, 0x2d, 0x38, 0x63, // t - u t f - 8 c
	0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3d, 0x69, // h a r s e t - i
	0x73, 0x6f, 0x2d, 0x38, 0x38, 0x35, 0x39, 0x2d, // s o - 8 8 5 9 -
	0x31, 0x2c, 0x75, 0x74, 0x66, 0x2d, 0x2c, 0x2a, // 1 - u t f - - -
	0x2c, 0x65, 0x6e, 0x71, 0x3d, 0x30, 0x2e, // - e n q - 0 -
}

var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// hasControlBitSet returns true if the passsed bytes have SPDY control bit set.
// SPDY frames can be either control frames or data frames. A control frame has
// control bit set to 1 and a data frame has it set to 0.
func hasControlBitSet(frame []byte) bool {
	return frame[0]&0x80 == 128 // 0x80
}

// isSPDYFrame validates that the input bytes start with a valid SPDY frame
// header.
func isSPDYFrameHeader(f []byte) bool {
	if hasControlBitSet(f) {
		// If this is a control frame, version and type must be set.
		return controlFrameVersion(f) != uint16(0) && uint16(controlFrameType(f)) != uint16(0)
	}
	// If this is a data frame, stream ID must be set.
	return dataFrameStreamID(f) != uint32(0)
}

// controlFrameType returns the type of a SPDY control frame.
// See https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6
func controlFrameType(f []byte) ControlFrameType {
	return ControlFrameType(binary.BigEndian.Uint16(f[2:4]))
}

// spdyControlFrameVersion returns SPDY version extracted from input bytes that
// must be a SPDY control frame.
func controlFrameVersion(frame []byte) uint16 {
	bs := binary.BigEndian.Uint16(frame[0:2]) // first 16 bits
	return bs & 0x7f                          // discard control bit
}

// spdyDataFrameStreamID returns stream ID for an SPDY data frame passed as the
// input data slice. StreaID is contained within bits [0-31) of a data frame
// header.
func dataFrameStreamID(frame []byte) uint32 {
	return binary.BigEndian.Uint32(frame[0:4]) & 0x7f
}

func readInt24(b []byte) int {
	_ = b[2] // bounds check hint to compiler; see golang.org/issue/14808
	return int(b[0])<<16 | int(b[1])<<8 | int(b[2])
}

// Headers in SPDY header name/value block are separated by a 0 byte.
// https://www.ietf.org/archive/id/draft-mbelshe-httpbis-spdy-00.txt section 2.6.10
var headerSep = []byte{0}

type recOpts struct {
	failOpen      bool
	recorderAddrs []netip.AddrPort
	conn          net.Conn
	brw           *bufio.ReadWriter
	ns            string
	pod           string
}

func sessionForbiddenResp(msg string) http.Response {
	b := io.NopCloser(bytes.NewBuffer([]byte(msg)))
	return http.Response{Status: http.StatusText(http.StatusForbidden), StatusCode: http.StatusForbidden, Body: b}
}
