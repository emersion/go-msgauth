//+build ignore

package main

import (
	"flag"
	"log"
	"net"
	"net/textproto"
	"os"
	"os/signal"
	"strings"
	"syscall"

	//"github.com/emersion/go-msgauth/dmarc"
	"github.com/emersion/go-milter"
	"github.com/emersion/go-msgauth/authres"
)

var (
	identity   string
	authServer string
	listenURI  string
)

func init() {
	flag.StringVar(&identity, "i", "", "Server identity (default: system hostname)")
	flag.StringVar(&authServer, "a", "", "Trusted authentication server (default: identity)")
	flag.StringVar(&listenURI, "l", "unix:///tmp/dkim-milter.sock", "Listen URI")
	flag.Parse()
}

type session struct {
	authResDelete []int
}

func (s *session) Connect(host string, family string, port uint16, addr net.IP, m *milter.Modifier) (milter.Response, error) {
	return nil, nil
}

func (s *session) Helo(name string, m *milter.Modifier) (milter.Response, error) {
	return nil, nil
}

func (s *session) MailFrom(from string, m *milter.Modifier) (milter.Response, error) {
	return nil, nil
}

func (s *session) RcptTo(rcptTo string, m *milter.Modifier) (milter.Response, error) {
	return nil, nil
}

func (s *session) Header(name string, value string, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func parseAddressDomain(s string) (string, error) {
	addr, err := mail.ParseAddress(s)
	if err != nil {
		return "", err
	}

	parts := strings.SplitN(addr.Address, "@", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("dmarc-milter: malformed address: missing '@'")
	}

	return parts[1], nil
}

func hasDMARC(results []authres.Result) bool {
	for _, res := range results {
		if _, ok := res.(*authres.DMARCResult); ok {
			return true
		}
	}
	return false
}

func (s *session) processAuthRes(field string) error {
	id, results, err := authres.Parse(field)
	if err != nil {
		// Delete fields we can't parse, because other implementations might
		// accept malformed fields
		s.authResDelete = append(s.authResDelete, i)
		return nil
	}

	if strings.EqualFold(id, identity) && hasDMARC(results) {
		// This is our Authentication-Results field, and it contains a DMARC
		// result. Delete the header field.
		s.authResDelete = append(s.authResDelete, i)
		return nil
	}

	if strings.EqualFold(id, authServer) {
		// This is an Authentication-Results field we can trust

	}

	return nil
}

func (s *session) evaluate(h textproto.MIMEHeader, m *milter.Modifier) (*authres.DMARCResult, error) {
	from := h.Get("From")
	if from == "" {
		return "", fmt.Errorf("dmarc-milter: missing From header field")
	}
	domain, err := parseAddressDomain(from)
	if err != nil {
		return "", fmt.Errorf("dmarc-milter: malformed From header field: %v", err)
	}

	noneResult := &authres.DMARCResult{
		Result: authres.ResultNone,
		From:   from,
	}

	record, err := dmarc.Lookup(domain)
	if err == dmarc.ErrNoPolicy {
		// TODO: use golang.org/x/net/publicsuffix to query the top-level DMARC record
		return noneResult, nil
	} else if err != nil {
		return "", err
	}

	fields := h["Authentication-Results"]
	for i, field := range fields {
		if err := s.processAuthRes(field, i); err != nil {
			return nil, err
		}

		id, results, err := authres.Parse(field)
		if err != nil {
		}

		// Delete any existing Authentication-Results header field with our identity
		if shouldDeleteAuthRes(field) {
			s.authResDelete = append(s.authResDelete, i)
		}
	}

	return &authres.DMARCResult{
		Result: authres.ResultPass,
		From: from,
	}, nil
}

func (s *session) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	result, err := s.evaluate(h, m)
	if err != nil {
		if result == nil {
			result = &authres.Result{
				Result: 
				From: h.Get("From"),
			}
		}
	}

	return milter.RespContinue, nil
}

func (s *session) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	return milter.RespContinue, nil
}

func (s *session) Body(m *milter.Modifier) (milter.Response, error) {
	for _, index := range s.authResDelete {
		if err := m.ChangeHeader(index, "Authentication-Results", ""); err != nil {
			return nil, err
		}
	}

	return milter.RespAccept, nil
}

func main() {
	if identity == "" {
		var err error
		if identity, err = os.Hostname(); err != nil {
			log.Fatalf("Failed to get system hostname: %v", err)
		}
	}
	if authServer == "" {
		authServer = identity
	}

	parts := strings.SplitN(listenURI, "://", 2)
	if len(parts) != 2 {
		log.Fatal("Invalid listen URI")
	}
	listenNetwork, listenAddr := parts[0], parts[1]

	s := milter.Server{
		NewMilter: func() milter.Milter {
			return &session{}
		},
		Actions:  milter.OptAddHeader | milter.OptChangeHeader,
		Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoMailFrom | milter.OptNoRcptTo | milter.OptNoBody,
	}

	ln, err := net.Listen(listenNetwork, listenAddr)
	if err != nil {
		log.Fatal("Failed to setup listener: ", err)
	}

	// Closing the listener will unlink the unix socket, if any
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		if err := s.Close(); err != nil {
			log.Fatal("Failed to close server: ", err)
		}
	}()

	log.Println("Milter listening at", listenURI)
	if err := s.Serve(ln); err != nil && err != milter.ErrServerClosed {
		log.Fatal("Failed to serve: ", err)
	}
}
