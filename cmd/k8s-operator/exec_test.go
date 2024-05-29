// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
	"tailscale.com/tstest"
	"tailscale.com/tstime"
)

// Test_Writes tests that 1 or more Write calls to spdyRemoteConnRecorder
// results in the expected data being forwarded to the original destination and
// the session recorder.
func Test_Writes(t *testing.T) {
	var stdoutStreamID, stderrStreamID uint32 = 1, 2
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	cl := tstest.NewClock(tstest.ClockOpts{})
	tests := []struct {
		name          string
		inputs        [][]byte
		wantForwarded []byte
		wantRecorded  []byte
	}{
		{
			name:          "single_write_control_frame_with_payload",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5},
		},
		{
			name:          "two_writes_control_frame_with_leftover",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1}, {0x0, 0x0, 0x0, 0x1, 0x5, 0x80, 0x3}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1, 0x5},
		},
		{
			name:          "single_write_stdout_data_frame",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
		},
		{
			name:          "single_write_stdout_data_frame_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  castLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
		{
			name:          "single_write_stderr_data_frame_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  castLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
		{
			name:          "single_data_frame_unknow_stream_with_payload",
			inputs:        [][]byte{{0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x0, 0x0, 0x0, 0x7, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
		},
		{
			name:          "control_frame_and_data_frame_split_across_two_writes",
			inputs:        [][]byte{{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1}, {0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5}},
			wantForwarded: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, 0x3, 0x4, 0x5},
			wantRecorded:  castLine(t, []byte{0x1, 0x2, 0x3, 0x4, 0x5}, cl),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &testConn{}
			sr := &testSessionRecorder{}
			lw := &loggingWriter{
				sessionRecorder: sr,
				clock:           cl,
				start:           cl.Now(),
				log:             zl.Sugar(),
			}

			c := &spdyRemoteConnRecorder{
				Conn: tc,
				log:  zl.Sugar(),
				lw:   lw,
			}

			c.stdoutStreamID.Store(stdoutStreamID)
			c.stderrStreamID.Store(stderrStreamID)
			for i, input := range tt.inputs {
				if _, err := c.Write(input); err != nil {
					t.Errorf("[%d] spdyRemoteConnRecorder.Write() unexpected error %v", i, err)
				}
			}

			// Assert that the expected bytes have been forwarded to the original destination.
			gotForwarded := tc.writeBuf.Bytes()
			if !reflect.DeepEqual(gotForwarded, tt.wantForwarded) {
				t.Errorf("expected bytes not forwarded, wants\n%v\ngot\n%v", tt.wantForwarded, gotForwarded)
			}

			// Assert that the expected bytes have been forwarded to the session recorder.
			gotRecorded := sr.buf.Bytes()
			if !reflect.DeepEqual(gotRecorded, tt.wantRecorded) {
				t.Errorf("expected bytes not recorded, wants\n%v\ngot\n%v", tt.wantRecorded, gotRecorded)
			}
		})
	}
}

func Test_determineRecorderConfig(t *testing.T) {
	addr1, addr2 := netip.MustParseAddrPort("[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:80"), netip.MustParseAddrPort("100.99.99.99:80")
	tests := []struct {
		name                  string
		wantFailOpen          bool
		wantRecorderAddresses []netip.AddrPort
		who                   *apitype.WhoIsResponse
	}{
		{
			name:                  "two_ips_fail_closed",
			who:                   whoResp(map[string][]string{string(tailcfg.PeerCapabilityKubernetes): {`{"recorderAddrs":["[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:80","100.99.99.99:80"],"enforceRecorder":true}`}}),
			wantRecorderAddresses: []netip.AddrPort{addr1, addr2},
		},
		{
			name:                  "two_ips_fail_open",
			who:                   whoResp(map[string][]string{string(tailcfg.PeerCapabilityKubernetes): {`{"recorderAddrs":["[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:80","100.99.99.99:80"]}`}}),
			wantRecorderAddresses: []netip.AddrPort{addr1, addr2},
			wantFailOpen:          true,
		},
		{
			name:                  "odd_rule_combination_fail_closed",
			who:                   whoResp(map[string][]string{string(tailcfg.PeerCapabilityKubernetes): {`{"recorderAddrs":["100.99.99.99:80"],"enforceRecorder":false}`, `{"recorderAddrs":["[fd7a:115c:a1e0:ab12:4843:cd96:626b:628b]:80"]}`, `{"enforceRecorder":true,"impersonate":{"groups":["system:masters"]}}`}}),
			wantRecorderAddresses: []netip.AddrPort{addr2, addr1},
		},
		{
			name:         "no_caps",
			who:          whoResp(map[string][]string{}),
			wantFailOpen: true,
		},
		{
			name:         "no_recorder_caps",
			who:          whoResp(map[string][]string{"foo": {`{"x":"y"}`}, string(tailcfg.PeerCapabilityKubernetes): {`{"impersonate":{"groups":["system:masters"]}}`}}),
			wantFailOpen: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotFailOpen, gotRecorderAddresses, err := determineRecorderConfig(tt.who)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotFailOpen != tt.wantFailOpen {
				t.Errorf("determineRecorderConfig() gotFailOpen = %v, want %v", gotFailOpen, tt.wantFailOpen)
			}
			if !reflect.DeepEqual(gotRecorderAddresses, tt.wantRecorderAddresses) {
				t.Errorf("determineRecorderConfig() gotRecorderAddresses = %v, want %v", gotRecorderAddresses, tt.wantRecorderAddresses)
			}
		})
	}
}

func Test_spdyFrame_Parse(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		gotBytes  []byte
		wantFrame spdyFrame
		wantOk    bool
		wantErr   bool
	}{
		{
			name:     "control_frame_syn_stream",
			gotBytes: []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0}, // big endian
			wantFrame: spdyFrame{
				Version: 3,
				Type:    1,
				Ctrl:    true,
				Raw:     []byte{0x80, 0x3, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0},
				Payload: []byte{},
			},
			wantOk: true,
		},
		{
			name:     "control_frame_syn_reply",
			gotBytes: []byte{0x80, 0x3, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0}, // big endian
			wantFrame: spdyFrame{
				Ctrl:    true,
				Version: 3,
				Type:    2,
				Raw:     []byte{0x80, 0x3, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0},
				Payload: []byte{},
			},
			wantOk: true,
		},
		{
			name:     "control_frame_headers",
			gotBytes: []byte{0x80, 0x3, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0}, // big endian
			wantFrame: spdyFrame{
				Ctrl:    true,
				Version: 3,
				Type:    8,
				Raw:     []byte{0x80, 0x3, 0x0, 0x8, 0x0, 0x0, 0x0, 0x0},
				Payload: []byte{},
			},
			wantOk: true,
		},
		{
			name:     "data_frame_stream_id_5",
			gotBytes: []byte{0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0}, // big endian
			wantFrame: spdyFrame{
				Payload:  []byte{},
				StreamID: 5,
				Raw:      []byte{0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x0},
			},
			wantOk: true,
		},
		{
			name:     "frame_with_incomplete_header",
			gotBytes: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		},
		{
			name:     "frame_with_incomplete_payload",
			gotBytes: []byte{0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x2}, // header specifies payload length of 2
		},
		{
			name:     "control_bit_set_not_spdy_frame",
			gotBytes: []byte{0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, // header specifies payload length of 2
			wantErr:  true,
		},
		{
			name:     "control_bit_not_set_not_spdy_frame",
			gotBytes: []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, // header specifies payload length of 2
			wantErr:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sf := &spdyFrame{}
			gotOk, err := sf.Parse(tt.gotBytes, zl.Sugar())
			if (err != nil) != tt.wantErr {
				t.Errorf("spdyFrame.Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOk != tt.wantOk {
				t.Errorf("spdyFrame.Parse() = %v, want %v", gotOk, tt.wantOk)
			}
			if diff := cmp.Diff(*sf, tt.wantFrame); diff != "" {
				t.Errorf("Unexpected SPDY frame (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_spdyFrame_parseHeaders(t *testing.T) {
	zl, err := zap.NewDevelopment()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		isCtrl     bool
		payload    []byte
		typ        ControlFrameType
		wantHeader http.Header
		wantErr    bool
	}{
		{
			name:       "syn_stream_with_header",
			payload:    payload(t, map[string]string{"Streamtype": "stdin"}, SYN_STREAM),
			typ:        SYN_STREAM,
			isCtrl:     true,
			wantHeader: header(map[string]string{"Streamtype": "stdin"}),
		},
		{
			name:    "syn_ping",
			payload: payload(t, nil, SYN_PING),
			typ:     SYN_PING,
			isCtrl:  true,
		},
		{
			name:       "syn_reply_headers",
			payload:    payload(t, map[string]string{"foo": "bar", "bar": "baz"}, SYN_REPLY),
			typ:        SYN_REPLY,
			isCtrl:     true,
			wantHeader: header(map[string]string{"foo": "bar", "bar": "baz"}),
		},
		{
			name:    "syn_reply_no_headers",
			payload: payload(t, nil, SYN_REPLY),
			typ:     SYN_REPLY,
			isCtrl:  true,
		},
		{
			name:    "syn_stream_too_short_payload",
			payload: []byte{0, 1, 2, 3, 4},
			typ:     SYN_STREAM,
			isCtrl:  true,
			wantErr: true,
		},
		{
			name:    "syn_reply_too_short_payload",
			payload: []byte{0, 1, 2},
			typ:     SYN_REPLY,
			isCtrl:  true,
			wantErr: true,
		},
		{
			name:    "syn_ping_too_short_payload",
			payload: []byte{0, 1, 2},
			typ:     SYN_PING,
			isCtrl:  true,
			wantErr: true,
		},
		{
			name:    "not_a_control_frame",
			payload: []byte{0, 1, 2, 3},
			typ:     SYN_PING,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		var reader zlibReader
		t.Run(tt.name, func(t *testing.T) {
			sf := &spdyFrame{
				Ctrl:    tt.isCtrl,
				Type:    tt.typ,
				Payload: tt.payload,
			}
			gotHeader, err := sf.parseHeaders(&reader, zl.Sugar())
			if (err != nil) != tt.wantErr {
				t.Errorf("spdyFrame.parseHeaders() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(gotHeader, tt.wantHeader) {
				t.Errorf("spdyFrame.parseHeaders() = %v, want %v", gotHeader, tt.wantHeader)
			}
		})
	}
}

// payload takes a control frame type and a map with 0 or more header keys and
// values and return a SPDY control frame payload with the header as SPDY zlib
// compressed header name/value block. The block is the only field that can be
// tested for correctness and it is in the correct position in for the control
// frame type.
func payload(t *testing.T, headerM map[string]string, typ ControlFrameType) []byte {
	t.Helper()

	buf := bytes.NewBuffer([]byte{})
	writeControlFramePayloadBeforeHeaders(t, buf, headerM, typ)
	if len(headerM) == 0 {
		return buf.Bytes()
	}

	w, err := zlib.NewWriterLevelDict(buf, zlib.BestCompression, spdyTxtDictionary)
	if err != nil {
		t.Fatalf("error creating new zlib writer: %v", err)
	}
	if len(headerM) != 0 {
		writeHeaderValueBlock(t, w, headerM)
	}
	if err != nil {
		t.Fatalf("error writing headers: %v", err)
	}
	w.Flush()
	return buf.Bytes()
}

func writeControlFramePayloadBeforeHeaders(t *testing.T, w io.Writer, headerM map[string]string, typ ControlFrameType) {
	switch typ {
	case SYN_STREAM:
		// needs 10 bytes in payload before any headers
		if err := binary.Write(w, binary.BigEndian, [10]byte{0}); err != nil {
			t.Fatalf("writing payload: %v", err)
		}
	case SYN_REPLY:
		// needs 4 bytes in payload before any headers
		if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
			t.Fatalf("writing payload: %v", err)
		}
	case SYN_PING:
		// needs 4 bytes in payload
		if err := binary.Write(w, binary.BigEndian, uint32(0)); err != nil {
			t.Fatalf("writing payload: %v", err)
		}
	default:
		t.Fatalf("unexpected frame type: %v", typ)
	}
}

// writeHeaderValue block takes http.Header and zlib writer, writes the headers
// as SPDY zlib compressed bytes to the writer.
// Adopted from https://github.com/moby/spdystream/blob/v0.2.0/spdy/write.go#L171-L198 (which is also what Kubernetes uses).
func writeHeaderValueBlock(t *testing.T, w io.Writer, headerM map[string]string) {
	t.Helper()
	h := header(headerM)
	if err := binary.Write(w, binary.BigEndian, uint32(len(h))); err != nil {
		t.Fatalf("error writing header block length: %v", err)
	}
	for name, values := range h {
		if err := binary.Write(w, binary.BigEndian, uint32(len(name))); err != nil {
			t.Fatalf("error writing name length for name %q: %v", name, err)
		}
		name = strings.ToLower(name)
		if _, err := io.WriteString(w, name); err != nil {
			t.Fatalf("error writing name %q: %v", name, err)
		}
		v := strings.Join(values, string(headerSep))
		if err := binary.Write(w, binary.BigEndian, uint32(len(v))); err != nil {
			t.Fatalf("error writing value length for value %q: %v", v, err)
		}
		if _, err := io.WriteString(w, v); err != nil {
			t.Fatalf("error writing value %q: %v", v, err)
		}
	}
}

func header(hs map[string]string) http.Header {
	h := make(http.Header, len(hs))
	for key, val := range hs {
		h.Add(key, val)
	}
	return h
}

func whoResp(capMap map[string][]string) *apitype.WhoIsResponse {
	resp := &apitype.WhoIsResponse{
		CapMap: tailcfg.PeerCapMap{},
	}
	for cap, rules := range capMap {
		resp.CapMap[tailcfg.PeerCapability(cap)] = raw(rules...)
	}
	return resp
}

func raw(in ...string) []tailcfg.RawMessage {
	var out []tailcfg.RawMessage
	for _, i := range in {
		out = append(out, tailcfg.RawMessage(i))
	}
	return out
}

func castLine(t *testing.T, p []byte, clock tstime.Clock) []byte {
	t.Helper()
	j, err := json.Marshal([]any{
		clock.Now().Sub(clock.Now()).Seconds(),
		"o",
		string(p),
	})
	if err != nil {
		t.Fatalf("error marshalling cast line: %v", err)
	}
	return append(j, '\n')
}

type testConn struct {
	net.Conn
	// writeBuf contains whatever was send to the conn via Write.
	writeBuf bytes.Buffer
	// readBuf contains whatever was sent to the conn via Read.
	readBuf bytes.Buffer
}

var _ net.Conn = &testConn{}

func (tc *testConn) Read(b []byte) (int, error) {
	return tc.readBuf.Write(b)
}

func (tc *testConn) Write(b []byte) (int, error) {
	return tc.writeBuf.Write(b)
}

type testSessionRecorder struct {
	// buf holds data that was sent to the session recorder.
	buf bytes.Buffer
}

func (t *testSessionRecorder) Write(b []byte) (int, error) {
	return t.buf.Write(b)
}

func (t *testSessionRecorder) Close() error {
	t.buf.Reset()
	return nil
}
