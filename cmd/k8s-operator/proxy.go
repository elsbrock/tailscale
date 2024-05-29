// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"tailscale.com/client/tailscale"
	"tailscale.com/client/tailscale/apitype"
	tskube "tailscale.com/kube"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/util/clientmetric"
	"tailscale.com/util/ctxkey"
	"tailscale.com/util/multierr"
	"tailscale.com/util/set"
)

var whoIsKey = ctxkey.New("", (*apitype.WhoIsResponse)(nil))

var counterNumRequestsProxied = clientmetric.NewCounter("k8s_auth_proxy_requests_proxied")

type apiServerProxyMode int

func (a apiServerProxyMode) String() string {
	switch a {
	case apiserverProxyModeDisabled:
		return "disabled"
	case apiserverProxyModeEnabled:
		return "auth"
	case apiserverProxyModeNoAuth:
		return "noauth"
	default:
		return "unknown"
	}
}

const (
	apiserverProxyModeDisabled apiServerProxyMode = iota
	apiserverProxyModeEnabled
	apiserverProxyModeNoAuth
)

func parseAPIProxyMode() apiServerProxyMode {
	haveAuthProxyEnv := os.Getenv("AUTH_PROXY") != ""
	haveAPIProxyEnv := os.Getenv("APISERVER_PROXY") != ""
	switch {
	case haveAPIProxyEnv && haveAuthProxyEnv:
		log.Fatal("AUTH_PROXY and APISERVER_PROXY are mutually exclusive")
	case haveAuthProxyEnv:
		var authProxyEnv = defaultBool("AUTH_PROXY", false) // deprecated
		if authProxyEnv {
			return apiserverProxyModeEnabled
		}
		return apiserverProxyModeDisabled
	case haveAPIProxyEnv:
		var apiProxyEnv = defaultEnv("APISERVER_PROXY", "") // true, false or "noauth"
		switch apiProxyEnv {
		case "true":
			return apiserverProxyModeEnabled
		case "false", "":
			return apiserverProxyModeDisabled
		case "noauth":
			return apiserverProxyModeNoAuth
		default:
			panic(fmt.Sprintf("unknown APISERVER_PROXY value %q", apiProxyEnv))
		}
	}
	return apiserverProxyModeDisabled
}

// maybeLaunchAPIServerProxy launches the auth proxy, which is a small HTTP server
// that authenticates requests using the Tailscale LocalAPI and then proxies
// them to the kube-apiserver.
func maybeLaunchAPIServerProxy(zlog *zap.SugaredLogger, restConfig *rest.Config, s *tsnet.Server, mode apiServerProxyMode) {
	if mode == apiserverProxyModeDisabled {
		return
	}
	startlog := zlog.Named("launchAPIProxy")
	if mode == apiserverProxyModeNoAuth {
		restConfig = rest.AnonymousClientConfig(restConfig)
	}
	cfg, err := restConfig.TransportConfig()
	if err != nil {
		startlog.Fatalf("could not get rest.TransportConfig(): %v", err)
	}

	// Kubernetes uses SPDY for exec and port-forward, however SPDY is
	// incompatible with HTTP/2; so disable HTTP/2 in the proxy.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig, err = transport.TLSConfigFor(cfg)
	if err != nil {
		startlog.Fatalf("could not get transport.TLSConfigFor(): %v", err)
	}
	tr.TLSNextProto = make(map[string]func(authority string, c *tls.Conn) http.RoundTripper)

	rt, err := transport.HTTPWrappersForConfig(cfg, tr)
	if err != nil {
		startlog.Fatalf("could not get rest.TransportConfig(): %v", err)
	}
	go runAPIServerProxy(s, rt, zlog.Named("apiserver-proxy"), mode, restConfig.Host)
}

// runAPIServerProxy runs an HTTP server that authenticates requests using the
// Tailscale LocalAPI and then proxies them to the Kubernetes API.
// It listens on :443 and uses the Tailscale HTTPS certificate.
// s will be started if it is not already running.
// rt is used to proxy requests to the Kubernetes API.
//
// mode controls how the proxy behaves:
//   - apiserverProxyModeDisabled: the proxy is not started.
//   - apiserverProxyModeEnabled: the proxy is started and requests are impersonated using the
//     caller's identity from the Tailscale LocalAPI.
//   - apiserverProxyModeNoAuth: the proxy is started and requests are not impersonated and
//     are passed through to the Kubernetes API.
//
// It never returns.
func runAPIServerProxy(s *tsnet.Server, rt http.RoundTripper, log *zap.SugaredLogger, mode apiServerProxyMode, host string) {
	if mode == apiserverProxyModeDisabled {
		return
	}
	ln, err := s.Listen("tcp", ":443")
	if err != nil {
		log.Fatalf("could not listen on :443: %v", err)
	}
	u, err := url.Parse(host)
	if err != nil {
		log.Fatalf("runAPIServerProxy: failed to parse URL %v", err)
	}

	lc, err := s.LocalClient()
	if err != nil {
		log.Fatalf("could not get local client: %v", err)
	}

	ap := &apiserverProxy{
		log:         log,
		lc:          lc,
		mode:        mode,
		upstreamURL: u,
		s:           s,
	}
	ap.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			ap.addImpersonationHeadersAsRequired(pr.Out)
		},
		Transport: rt,
	}
	hs := &http.Server{
		// Kubernetes uses SPDY for exec and port-forward, however SPDY is
		// incompatible with HTTP/2; so disable HTTP/2 in the proxy.
		TLSConfig: &tls.Config{
			GetCertificate: lc.GetCertificate,
			NextProtos:     []string{"http/1.1"},
		},
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		Handler:      ap,
	}
	log.Infof("API server proxy in %q mode is listening on %s", mode, ln.Addr())
	if err := hs.ServeTLS(ln, "", ""); err != nil {
		log.Fatalf("runAPIServerProxy: failed to serve %v", err)
	}
}

// apiserverProxy is an http.Handler that authenticates requests using the Tailscale
// LocalAPI and then proxies them to the Kubernetes API.
type apiserverProxy struct {
	log *zap.SugaredLogger
	lc  *tailscale.LocalClient
	rp  *httputil.ReverseProxy

	mode        apiServerProxyMode
	s           *tsnet.Server
	upstreamURL *url.URL
}

func (h *apiserverProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	who, err := h.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		h.log.Errorf("failed to authenticate caller: %v", err)
		http.Error(w, "failed to authenticate caller", http.StatusInternalServerError)
		return
	}
	if who == nil {
		h.log.Errorf("unable to determine caller from remote addr %v", r.RemoteAddr)
	}
	counterNumRequestsProxied.Add(1)
	if r.Method != "POST" || r.Header.Get("Upgrade") != "SPDY/3.1" {
		h.rp.ServeHTTP(w, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
		return
	}

	spdyH := &spdyHijacker{
		s:              h.s,
		req:            r,
		who:            who,
		ResponseWriter: w,
		log:            h.log,
	}

	h.rp.ServeHTTP(spdyH, r.WithContext(whoIsKey.WithValue(r.Context(), who)))
}

func (h *apiserverProxy) addImpersonationHeadersAsRequired(r *http.Request) {
	r.URL.Scheme = h.upstreamURL.Scheme
	r.URL.Host = h.upstreamURL.Host
	if h.mode == apiserverProxyModeNoAuth {
		// If we are not providing authentication, then we are just
		// proxying to the Kubernetes API, so we don't need to do
		// anything else.
		return
	}

	// We want to proxy to the Kubernetes API, but we want to use
	// the caller's identity to do so. We do this by impersonating
	// the caller using the Kubernetes User Impersonation feature:
	// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation

	// Out of paranoia, remove all authentication headers that might
	// have been set by the client.
	r.Header.Del("Authorization")
	r.Header.Del("Impersonate-Group")
	r.Header.Del("Impersonate-User")
	r.Header.Del("Impersonate-Uid")
	for k := range r.Header {
		if strings.HasPrefix(k, "Impersonate-Extra-") {
			r.Header.Del(k)
		}
	}

	// Now add the impersonation headers that we want.
	if err := addImpersonationHeaders(r, h.log); err != nil {
		log.Fatalf("failed to add impersonation headers: " + err.Error())
	}
}

// spdyHijacker implements net/http#Hijacker interface. It allows to intercept
// kubectl exec sessions and send them to an available tsrecorder instance if so
// configured, before allowing the API server proxy to forward them to kube API server.
// https://pkg.go.dev/net/http#Hijacker
type spdyHijacker struct {
	http.ResponseWriter
	s   *tsnet.Server
	req *http.Request
	who *apitype.WhoIsResponse
	log *zap.SugaredLogger
}

// Hijack looks at a connection from a client and, if the request if for kubectl
// exec and session recording is required, configures the request to be
// forwarded to an available tsrecorder instance else returns the connection as
// is for the API server proxy to forward it to the kube API server.
func (h *spdyHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	reqConn, brw, err := h.ResponseWriter.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// e.g. "/api/v1/namespaces/default/pods/foobar/exec
	suf, ok := strings.CutPrefix(h.req.URL.Path, "/api/v1/namespaces/")
	if !ok {
		return reqConn, brw, nil
	}
	ns, suf, ok := strings.Cut(suf, "/pods/")
	if !ok {
		return reqConn, brw, nil
	}
	pod, action, ok := strings.Cut(suf, "/")
	if !ok {
		return reqConn, brw, nil
	}
	if action != "exec" {
		return reqConn, brw, nil
	}

	failOpen, addrs, err := determineRecorderConfig(h.who)
	if err != nil {
		return nil, nil, fmt.Errorf("error trying to determine whether the 'kubectl exec' session needs to be recorded: %w", err)
	}
	// No need to record
	if failOpen && len(addrs) == 0 {
		return reqConn, brw, nil
	}

	// Log this line only after it has been determined that users have set
	// some recording config in grants, else it might be confusing.
	h.log.Infof("recorder addrs: %v, failOpen: %v", addrs, failOpen)

	if !failOpen && len(addrs) == 0 {
		defer reqConn.Close()
		msg := "forbidden: 'kubectl exec' session must be recorded, but no recorders are available."
		resp := sessionForbiddenResp(msg)
		err = resp.Write(reqConn)
		if err != nil {
			return nil, nil, multierr.New(errors.New(msg), err)
		}
		return nil, nil, errors.New(msg)
	}
	recOpts := recOpts{
		failOpen:      failOpen,
		recorderAddrs: addrs,
		conn:          reqConn,
		brw:           brw,
		ns:            ns,
		pod:           pod,
	}
	conn, err := h.setupRecording(recOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting up session recording: %w", err)
	}
	return conn, brw, nil
}

// addImpersonationHeaders adds the appropriate headers to r to impersonate the
// caller when proxying to the Kubernetes API. It uses the WhoIsResponse stashed
// in the context by the apiserverProxy.
func addImpersonationHeaders(r *http.Request, log *zap.SugaredLogger) error {
	log = log.With("remote", r.RemoteAddr)
	who := whoIsKey.Value(r.Context())
	rules, err := tailcfg.UnmarshalCapJSON[tskube.KubernetesCapRule](who.CapMap, tailcfg.PeerCapabilityKubernetes)
	if len(rules) == 0 && err == nil {
		// Try the old capability name for backwards compatibility.
		rules, err = tailcfg.UnmarshalCapJSON[tskube.KubernetesCapRule](who.CapMap, oldCapabilityName)
	}
	if err != nil {
		return fmt.Errorf("failed to unmarshal capability: %v", err)
	}

	var groupsAdded set.Slice[string]
	for _, rule := range rules {
		if rule.Impersonate == nil {
			continue
		}
		for _, group := range rule.Impersonate.Groups {
			if groupsAdded.Contains(group) {
				continue
			}
			r.Header.Add("Impersonate-Group", group)
			groupsAdded.Add(group)
			log.Debugf("adding group impersonation header for user group %s", group)
		}
	}

	if !who.Node.IsTagged() {
		r.Header.Set("Impersonate-User", who.UserProfile.LoginName)
		log.Debugf("adding user impersonation header for user %s", who.UserProfile.LoginName)
		return nil
	}
	// "Impersonate-Group" requires "Impersonate-User" to be set, so we set it
	// to the node FQDN for tagged nodes.
	nodeName := strings.TrimSuffix(who.Node.Name, ".")
	r.Header.Set("Impersonate-User", nodeName)
	log.Debugf("adding user impersonation header for node name %s", nodeName)

	// For legacy behavior (before caps), set the groups to the nodes tags.
	if groupsAdded.Slice().Len() == 0 {
		for _, tag := range who.Node.Tags {
			r.Header.Add("Impersonate-Group", tag)
			log.Debugf("adding group impersonation header for node tag %s", tag)
		}
	}
	return nil
}

const (
	// oldCapabilityName is a legacy form of
	// tailfcg.PeerCapabilityKubernetes capability. The only capability rule
	// that is respected for this form is group impersonation - for
	// backwards compatibility reasons.
	// TODO (irbekrm): determine if anyone uses this and remove if possible.
	oldCapabilityName = "https://" + tailcfg.PeerCapabilityKubernetes
)
