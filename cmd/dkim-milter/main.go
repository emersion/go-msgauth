package main

import (
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/textproto"
	"os"
	"strings"

	"github.com/emersion/go-dkim"
	"github.com/emersion/go-milter"
	"github.com/emersion/go-msgauth"
)

type session struct {
	identity      string
	authResDelete []int
	done          <-chan error
	verifs        []*dkim.Verification // only valid after done is closed
	pw            *io.PipeWriter
}

func newSession(identity string) *session {
	done := make(chan error, 1)
	pr, pw := io.Pipe()
	s := &session{
		identity: identity,
		done:     done,
		pw:       pw,
	}

	// TODO: limit max. number of signatures
	go func() {
		var err error
		s.verifs, err = dkim.Verify(pr)
		io.Copy(ioutil.Discard, pr)
		pr.Close()
		done <- err
		close(done)
	}()

	return s
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
	field := name + ": " + value + "\r\n"
	_, err := s.pw.Write([]byte(field))
	return milter.RespContinue, err
}

func getIdentity(authRes string) string {
	parts := strings.SplitN(authRes, ";", 2)
	return strings.TrimSpace(parts[0])
}

func (s *session) Headers(h textproto.MIMEHeader, m *milter.Modifier) (milter.Response, error) {
	// Write final CRLF to begin message body
	if _, err := s.pw.Write([]byte("\r\n")); err != nil {
		return nil, err
	}

	// Delete any existing Authentication-Results header field with our identity
	fields := h["Authentication-Results"]
	for i, field := range fields {
		if strings.EqualFold(s.identity, getIdentity(field)) {
			s.authResDelete = append(s.authResDelete, i)
		}
	}
	return milter.RespContinue, nil
}

func (s *session) BodyChunk(chunk []byte, m *milter.Modifier) (milter.Response, error) {
	_, err := s.pw.Write(chunk)
	return milter.RespContinue, err
}

func (s *session) Body(m *milter.Modifier) (milter.Response, error) {
	if err := s.pw.Close(); err != nil {
		return nil, err
	}

	for _, index := range s.authResDelete {
		if err := m.ChangeHeader(index, "Authentication-Results", ""); err != nil {
			return nil, err
		}
	}

	if err := <-s.done; err != nil {
		log.Printf("DKIM verification failed: %v", err)
		return milter.RespAccept, nil
	}

	results := make([]msgauth.Result, 0, len(s.verifs))

	if len(s.verifs) == 0 {
		results = append(results, &msgauth.DKIMResult{
			Value: msgauth.ResultNone,
		})
	}

	for _, verif := range s.verifs {
		if verif.Err != nil {
			log.Printf("DKIM verification failed for %v: %v", verif.Domain, verif.Err)
		}

		var val msgauth.ResultValue
		if verif.Err == nil {
			val = msgauth.ResultPass
		} else if dkim.IsPermFail(verif.Err) {
			val = msgauth.ResultPermError
		} else if dkim.IsTempFail(verif.Err) {
			val = msgauth.ResultTempError
		} else {
			val = msgauth.ResultFail
		}

		results = append(results, &msgauth.DKIMResult{
			Value:      val,
			Domain:     verif.Domain,
			Identifier: verif.Identifier,
		})
	}

	v := msgauth.Format(s.identity, results)
	err := m.InsertHeader(0, "Authentication-Results", v)
	return milter.RespAccept, err
}

var identity string
var listenURI string

func init() {
	flag.StringVar(&identity, "identity", "", "Server identity (defaults to hostname)")
	flag.StringVar(&listenURI, "listen", "unix:///tmp/dkim-milter.sock", "Listen URI")
}

func main() {
	flag.Parse()

	if identity == "" {
		var err error
		identity, err = os.Hostname()
		if err != nil {
			log.Fatal("Failed to read hostname:", err)
		}
	}

	parts := strings.SplitN(listenURI, "://", 2)
	if len(parts) != 2 {
		log.Fatal("Invalid listen URI")
	}
	listenNetwork, listenAddr := parts[0], parts[1]

	s := milter.Server{
		NewMilter: func() milter.Milter {
			return newSession(identity)
		},
		Actions:  milter.OptAddHeader | milter.OptChangeHeader,
		Protocol: milter.OptNoConnect | milter.OptNoHelo | milter.OptNoMailFrom | milter.OptNoRcptTo,
	}

	ln, err := net.Listen(listenNetwork, listenAddr)
	if err != nil {
		log.Fatal("Failed to setup listener:", err)
	}

	log.Println("Milter listening at", listenURI)
	if err := s.Serve(ln); err != nil {
		log.Fatal("Failed to serve:", err)
	}
}
