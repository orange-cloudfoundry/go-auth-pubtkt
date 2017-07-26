package pubtkt_test

import (
	. "github.com/orange-cloudfoundry/go-auth-pubtkt"

	"errors"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/orange-cloudfoundry/go-auth-pubtkt/pubtktfakes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
)

var _ = Describe("Middleware", func() {
	var fakePubTkt *FakeAuthPubTkt
	var funcFakePubTkt func(options AuthPubTktOptions) (AuthPubTkt, error)
	BeforeEach(func() {
		fakePubTkt = new(FakeAuthPubTkt)
		funcFakePubTkt = func(options AuthPubTktOptions) (AuthPubTkt, error) {
			return fakePubTkt, nil
		}
	})
	Context("ServeHTTP", func() {
		Context("When ticket is valid", func() {
			It("should serve the next handler", func() {
				expectedUrlPath := "handled by next handler"
				h, err := NewAuthPubTktHandler(
					AuthPubTktOptions{},
					http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						req.URL.Path = expectedUrlPath
					}),
					SetCreateAuthPubTktFunc(funcFakePubTkt),
				)
				Expect(err).ToNot(HaveOccurred())
				fakePubTkt.VerifyFromRequestReturns(&Ticket{}, nil)
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "http://localhost.com", nil)

				h.ServeHTTP(w, req)

				Expect(req.URL.Path).Should(Equal(expectedUrlPath))
			})
			It("should pass ticket in context", func() {
				h, err := NewAuthPubTktHandler(
					AuthPubTktOptions{},
					http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
					SetCreateAuthPubTktFunc(funcFakePubTkt),
				)
				Expect(err).ToNot(HaveOccurred())
				ticket := &Ticket{
					Uid: "user",
				}
				fakePubTkt.VerifyFromRequestReturns(ticket, nil)
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "http://localhost.com", nil)

				h.ServeHTTP(w, req)

				Expect(TicketRequest(req)).ShouldNot(BeNil())
				Expect(TicketRequest(req).Uid).Should(Equal("user"))
			})
			It("should rewrite authorization if needed in the request when it's simple fake basic auth requested", func() {
				h, err := NewAuthPubTktHandler(
					AuthPubTktOptions{TKTAuthFakeBasicAuth: true},
					http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
					SetCreateAuthPubTktFunc(funcFakePubTkt),
				)
				Expect(err).ToNot(HaveOccurred())
				ticket := &Ticket{
					Uid: "user",
				}
				fakePubTkt.VerifyFromRequestReturns(ticket, nil)
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "http://localhost.com", nil)

				h.ServeHTTP(w, req)

				user, password, _ := req.BasicAuth()
				Expect(user).Should(Equal("user"))
				Expect(password).Should(Equal("password"))
			})
			It("should rewrite authorization if needed in the request when it's simple bauth requested", func() {
				h, err := NewAuthPubTktHandler(
					AuthPubTktOptions{TKTAuthPassthruBasicAuth: true},
					http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
					SetCreateAuthPubTktFunc(funcFakePubTkt),
				)
				Expect(err).ToNot(HaveOccurred())
				ticket := &Ticket{
					Uid:   "user",
					Bauth: "myvalue",
				}
				fakePubTkt.VerifyFromRequestReturns(ticket, nil)
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "http://localhost.com", nil)

				h.ServeHTTP(w, req)

				req.Header.Get("Authorization")
				Expect(req.Header.Get("Authorization")).Should(Equal("myvalue"))
			})
			It("should rewrite authorization if needed in the request when it's crypted bauth requested", func() {
				key := "AZERTYUIOPQSDFGH"
				cryptedBauth := "6EAv9/i8HmAN3yr681s8OsNXJ4Xw0Qe70taHuUNvV7k=" // == mydata
				h, err := NewAuthPubTktHandler(
					AuthPubTktOptions{TKTAuthPassthruBasicAuth: true, TKTAuthPassthruBasicKey: key},
					http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
					SetCreateAuthPubTktFunc(funcFakePubTkt),
				)
				Expect(err).ToNot(HaveOccurred())
				ticket := &Ticket{
					Uid:   "user",
					Bauth: cryptedBauth,
				}
				fakePubTkt.VerifyFromRequestReturns(ticket, nil)
				w := httptest.NewRecorder()
				req, _ := http.NewRequest("GET", "http://localhost.com", nil)

				h.ServeHTTP(w, req)

				req.Header.Get("Authorization")
				Expect(req.Header.Get("Authorization")).Should(Equal("mydata"))
			})
		})
		Context("When ticket is not valid", func() {
			Context("And error is not recognized", func() {
				BeforeEach(func() {
					fakePubTkt.VerifyFromRequestReturns(nil, errors.New("unrecognized error"))
				})
				It("should create status code and text when no details is needed and error don't create panic", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
						SetStatus("mystatus", 400),
					)
					Expect(err).ToNot(HaveOccurred())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "http://localhost.com", nil)

					h.ServeHTTP(w, req)

					resp := w.Result()
					Expect(resp.StatusCode).Should(Equal(400))
					Expect(respToString(resp)).Should(Equal("mystatus"))
				})
				It("should create status code and text with detail when details is needed and error don't create panic", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
						SetStatus("mystatus", 400),
						ShowErrorDetails(),
					)
					Expect(err).ToNot(HaveOccurred())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "http://localhost.com", nil)

					h.ServeHTTP(w, req)

					resp := w.Result()
					Expect(resp.StatusCode).Should(Equal(400))
					Expect(respToString(resp)).Should(Equal("mystatus\nError details: unrecognized error"))
				})
				It("should panic with error when error create panic", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
						SetStatus("mystatus", 400),
						PanicOnError(),
					)
					Expect(err).ToNot(HaveOccurred())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "http://localhost.com", nil)

					defer func() {
						if r := recover(); r != nil {
							err, isErr := r.(error)
							Expect(isErr).Should(BeTrue(), "recover from error type")
							Expect(err.Error()).Should(Equal("unrecognized error"))
							return
						}
						Expect(true).Should(BeFalse(), "this should panic but it didn't")
					}()

					h.ServeHTTP(w, req)

				})
			})
			Context("And error is recognized", func() {
				It("should redirect to TKTAuthLoginURL when error is caused by unvalid signature", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{TKTAuthLoginURL: "http://login.redirect.com", TKTAuthBackArgName: "myback"},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
					)
					Expect(err).ToNot(HaveOccurred())
					fakePubTkt.VerifyFromRequestReturns(nil, NewErrSigNotValid())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "http://localhost.com", nil)

					h.ServeHTTP(w, req)

					resp := w.Result()
					Expect(resp.Header.Get("Location")).Should(Equal("http://login.redirect.com?myback=" + url.QueryEscape("http://localhost.com")))
				})
				It("should redirect to TKTAuthLoginURL when error is caused when no ticket is provided", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{TKTAuthLoginURL: "http://login.redirect.com", TKTAuthBackArgName: "myback"},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
					)
					Expect(err).ToNot(HaveOccurred())
					fakePubTkt.VerifyFromRequestReturns(nil, NewErrNoTicket())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "http://localhost.com", nil)

					h.ServeHTTP(w, req)

					resp := w.Result()
					Expect(resp.Header.Get("Location")).Should(Equal("http://login.redirect.com?myback=" + url.QueryEscape("http://localhost.com")))
				})
				It("should redirect to TKTAuthPostTimeoutURL when error is caused when ticket expired and method used is POST", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{TKTAuthPostTimeoutURL: "http://post.timeout.redirect.com", TKTAuthBackArgName: "myback"},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
					)
					Expect(err).ToNot(HaveOccurred())
					fakePubTkt.VerifyFromRequestReturns(nil, NewErrValidationExpired())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("POST", "http://localhost.com", nil)

					h.ServeHTTP(w, req)

					resp := w.Result()
					Expect(resp.Header.Get("Location")).Should(Equal("http://post.timeout.redirect.com?myback=" + url.QueryEscape("http://localhost.com")))
				})
				It("should redirect to TKTAuthPostTimeoutURL when error is caused when ticket expired and method used is not POST", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{TKTAuthTimeoutURL: "http://timeout.redirect.com", TKTAuthBackArgName: "myback"},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
					)
					Expect(err).ToNot(HaveOccurred())
					fakePubTkt.VerifyFromRequestReturns(nil, NewErrValidationExpired())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "http://localhost.com", nil)

					h.ServeHTTP(w, req)

					resp := w.Result()
					Expect(resp.Header.Get("Location")).Should(Equal("http://timeout.redirect.com?myback=" + url.QueryEscape("http://localhost.com")))
				})
				It("should redirect to TKTAuthRefreshURL when error is caused when graceful expired", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{TKTAuthRefreshURL: "http://refresh.redirect.com", TKTAuthBackArgName: "myback"},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
					)
					Expect(err).ToNot(HaveOccurred())
					fakePubTkt.VerifyFromRequestReturns(nil, NewErrGracePeriodExpired())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "http://localhost.com", nil)

					h.ServeHTTP(w, req)

					resp := w.Result()
					Expect(resp.Header.Get("Location")).Should(Equal("http://refresh.redirect.com?myback=" + url.QueryEscape("http://localhost.com")))
				})
				It("should redirect to TKTAuthUnauthURL when error is caused by no token matching tokens in ticket", func() {
					h, err := NewAuthPubTktHandler(
						AuthPubTktOptions{TKTAuthUnauthURL: "http://unauth.redirect.com", TKTAuthBackArgName: "myback"},
						http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {}),
						SetCreateAuthPubTktFunc(funcFakePubTkt),
					)
					Expect(err).ToNot(HaveOccurred())
					fakePubTkt.VerifyFromRequestReturns(nil, NewErrNoValidToken())
					w := httptest.NewRecorder()
					req, _ := http.NewRequest("GET", "http://localhost.com", nil)

					h.ServeHTTP(w, req)

					resp := w.Result()
					Expect(resp.Header.Get("Location")).Should(Equal("http://unauth.redirect.com?myback=" + url.QueryEscape("http://localhost.com")))
				})
			})
		})
	})
})

func respToString(resp *http.Response) string {
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(b)
}
