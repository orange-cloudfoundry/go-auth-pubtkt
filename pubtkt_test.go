package pubtkt_test

import (
	. "github.com/orange-cloudfoundry/go-auth-pubtkt"

	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Pubtkt", func() {

	Context("RawToTicket", func() {
		It("Should give correct ticket when it's not encrypted", func() {
			ticketRaw := "uid=myuser;validuntil=1;tokens=token1,token2;sig=mysignature"
			auth, err := NewAuthPubTkt(AuthPubTktOptions{TKTAuthPublicKey: "fake", TKTAuthCookieName: "fake", TKTAuthHeader: []string{"fake"}})
			Expect(err).ToNot(HaveOccurred())

			ticket, err := auth.RawToTicket(ticketRaw)
			Expect(err).ToNot(HaveOccurred())
			Expect(*ticket).Should(Equal(Ticket{
				Uid:        "myuser",
				Validuntil: time.Unix(1, 0),
				Tokens:     []string{"token1", "token2"},
				RawData:    "uid=myuser;validuntil=1;tokens=token1,token2",
				Sig:        "mysignature",
			}))
		})
		It("Should give correct ticket when it's encrypted", func() {
			ticketRaw := "NgJVDZTchnQ3CpQWRhLHExefvSPkFyLIaCyvnNy+XB/BHu+ah1ojR2ZBrALb0fIqKKdIpnVQ9OBuJl8MXa/NZw=="
			passPhrase := "mysuperpassphrase"
			auth, _ := NewAuthPubTkt(AuthPubTktOptions{
				TKTAuthPublicKey:           "fake",
				TKTAuthCookieName:          "fake",
				TKTAuthHeader:              []string{"fake"},
				TKTCypherTicketsWithPasswd: passPhrase,
				TKTCypherTicketsMethod:     "cbc",
			})
			ticket, err := auth.RawToTicket(ticketRaw)
			Expect(err).ToNot(HaveOccurred())
			Expect(*ticket).Should(Equal(Ticket{
				Uid:        "myuser",
				Validuntil: time.Unix(1, 0),
				Tokens:     []string{"token1", "token2"},
				Sig:        "mysignature",
				RawData:    "uid=myuser;validuntil=1;tokens=token1,token2",
			}))
		})
	})
	Context("RequestToTicket", func() {
		It("Should give correct ticket from cookie when it's set", func() {
			ticketRaw := "uid=myuser;validuntil=1;tokens=token1,token2;sig=mysignature"
			auth, err := NewAuthPubTkt(AuthPubTktOptions{
				TKTAuthPublicKey:  "fake",
				TKTAuthHeader:     []string{"cookie"},
				TKTAuthCookieName: "pubtkt",
			})
			Expect(err).ToNot(HaveOccurred())

			req, _ := http.NewRequest("GET", "http://local.com", nil)
			req.AddCookie(&http.Cookie{Name: "pubtkt", Value: url.QueryEscape(ticketRaw)})

			ticket, err := auth.RequestToTicket(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(*ticket).Should(Equal(Ticket{
				Uid:        "myuser",
				Validuntil: time.Unix(1, 0),
				Tokens:     []string{"token1", "token2"},
				Sig:        "mysignature",
				RawData:    "uid=myuser;validuntil=1;tokens=token1,token2",
			}))
		})
		It("Should give correct ticket from header if it's set when it's set", func() {
			ticketRaw := "uid=myuser;validuntil=1;tokens=token1,token2;sig=mysignature"
			auth, err := NewAuthPubTkt(AuthPubTktOptions{
				TKTAuthPublicKey:  "fake",
				TKTAuthCookieName: "fake",
				TKTAuthHeader:     []string{"x-authpubtkt"},
			})
			Expect(err).ToNot(HaveOccurred())

			req, _ := http.NewRequest("GET", "http://local.com", nil)
			req.Header.Set("x-authpubtkt", ticketRaw)

			ticket, err := auth.RequestToTicket(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(*ticket).Should(Equal(Ticket{
				Uid:        "myuser",
				Validuntil: time.Unix(1, 0),
				Tokens:     []string{"token1", "token2"},
				Sig:        "mysignature",
				RawData:    "uid=myuser;validuntil=1;tokens=token1,token2",
			}))
		})
		It("Should give correct ticket from cookie by cascading if no header is set", func() {
			ticketRaw := "uid=myuser;validuntil=1;tokens=token1,token2;sig=mysignature"
			auth, err := NewAuthPubTkt(AuthPubTktOptions{
				TKTAuthPublicKey:  "fake",
				TKTAuthHeader:     []string{"x-authpubtkt", "cookie"},
				TKTAuthCookieName: "pubtkt",
			})
			Expect(err).ToNot(HaveOccurred())

			req, _ := http.NewRequest("GET", "http://local.com", nil)
			req.AddCookie(&http.Cookie{Name: "pubtkt", Value: url.QueryEscape(ticketRaw)})

			ticket, err := auth.RequestToTicket(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(*ticket).Should(Equal(Ticket{
				Uid:        "myuser",
				Validuntil: time.Unix(1, 0),
				Tokens:     []string{"token1", "token2"},
				Sig:        "mysignature",
				RawData:    "uid=myuser;validuntil=1;tokens=token1,token2",
			}))
		})
		It("Should give an error if no header or cookie are set", func() {
			auth, err := NewAuthPubTkt(AuthPubTktOptions{
				TKTAuthPublicKey:  "fake",
				TKTAuthHeader:     []string{"x-authpubtkt", "cookie"},
				TKTAuthCookieName: "pubtkt",
			})
			Expect(err).ToNot(HaveOccurred())

			req, _ := http.NewRequest("GET", "http://local.com", nil)
			_, err = auth.RequestToTicket(req)
			Expect(err).Should(HaveOccurred())
			Expect(err).Should(MatchError(NewErrNoTicket().Error()))
		})
	})
	Context("Verify", func() {
		var defaultTicket *Ticket
		// with ticket data uid=myuser;cip=127.0.0.1;validuntil=1;tokens=token1,token2
		pubKeyRsa := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx5JJ32izx2rZF4L7cnfv
e4aMew22Lu5GwJ6YgOj1hXKwYjPk0l+qyvCVAPVSKEOEf7ehtL3h+/XEDV+DDrdC
ZSjSrzT+RRV5tnQ+x7nbibSwT/VewAU0yz+C5cVuX5QWWDQV8sY7sAvvnJ3HJkpc
HqQ0Jvk0+w212h+CnZpuakO3M7yfq3yv8u93mEyUwcmix9dXx/9Cuoe18KDjULrj
UVMRcaQeXlAFau9nzd14LYruU81ShWmHNzvgMWhT5jYiEBlfF6jHso5e3d1nlX0n
tU03Z0V1stilqjL9L9DFQZUnpyQJSGu3HS2pf+G0NFDQnETEryKuD0vPIa17C0yE
zQIDAQAB
-----END PUBLIC KEY-----`

		sha1Sig := "CLB5SmRpGGiYwUM76MXfVS+h9cp9nq3G6xQ13/XrvTOXon2lR903Wuixz/zEt2ljZm9gSosfZmpa12k3csEOKqwGvZCDHJCfb/EibY/xDXJjgGv89XMtIwYSmDjJ1GJOuPG0YERZALIyfHmMLJZOXq6QalzQ/PRRNeZn93k+8KeetsO33W785vnSqDMkwL9JIJHHcxSd4pJLPsSUCQVPXJN5mWZWI56J0KHZht08klKc2EFx39jd4QImjWEu188HvQ5/NO4L6COjS/J29JrAGWN3IRvu7gq7Krzcm8wdkL1Hf4r2vsS1unpT6E0MfaIqLZOa9FPsvIp3EP4M2ugwLg=="
		dss1Sig := "MC0CFQCUijdPIW3yHoPtru/my77rdVrJVAIUfdtGuRsTd1B2V2LCET/LILiX/II="
		pubKeyDsa := `-----BEGIN PUBLIC KEY-----
MIIDODCCAisGByqGSM44BAEwggIeAoIBAQDsgZumckiMIe4UNkxfHkg9OGiVJaDX
76g8oodG5dCwqxb5JN9QNeIj8mpyOPsVg0uq6v16MaCGkAwVIlIvCjBULMCzLdUP
N3Rcwf5rUWyrYu+nfs4XXEwFHMqOPl+GgkK3b6Z3jrf/FwjCuDJDqm6wvBVo1o5g
GIkfYZAn+pX8tpT8xeHXM5tCjeKEHz0Vwu6JahT03LmetqFCSoNJJi07Fa9NWyqJ
byJHi3lcIIJPimeCZsC2NC+rXzoJ292tfa2OgsON2btQLD/6daa7jdukpzL84FYA
qhqMJfaEEJgdoHlUrwxCEu6cCLUqWD2YaoRG7m69zQG4L5/vzCAH/AkZAhUAmjb+
JTswjkZ6og46tbkCaQ7JWFMCgf9iJkAD3D5gannM4q2kHaoPxmxPcMe93CstJ8Na
I4A69rTzYxJmpWz83HxCIh0JVWFtOajFguuUV3mTAmqIw1O3MFXLRiCWLSQLEFS4
oQ7jrFfuhKP1XC9gcTvyKLFhSyt2iU6j38XkZME1sH8McMEXVO+KfufsauZqYJni
1mNZ7uilWwkSEXIFfj91zdF1ELxwprsrwFFbClhTsLSgopx9/na0fOmi9pDyoJZV
ymo/dnF3/PF7guhF3Owj9JShzgKBGpEe3BB0bbhfvKHYE5QQOHF+qSGWDeXcEul1
lWqa8lAJyMnp5FCyIFYH1qNw5HBoayf7HlGaUd8oCk9q+boDggEFAAKCAQB8chaK
eH8/AMOUiOMUZulHGqF4MGLQDxDP854BDZSPcb10lUuXfRJvXdN1gM4T+E2oC3Jv
AeNepm7PqTSr23Hy+GQ7ey+LTO1Z2aSHjOf2rMOEJrqwj43zDxuRj5oMYstD3mR6
elGshc8N0HA7qIMoRdCkZfslh6vbd9SGQqIT3qkIh7jOcp8V3gi2fAkz5ZXmkODV
QOZkGj1O0vPk3+gVrVXKnQj5WF7wtT+iUEBs6L65hmXYMown4wzolJq+XT3lliAq
pzY+pD9CXCD6qkeXWXSxLfhlVs+42bPzebiS5lZr6yZ5knR0QM10oT+0ApODWmbd
StOB7bD9meH5/rOy
-----END PUBLIC KEY-----`
		BeforeEach(func() {
			TimeNowFunc = func() time.Time {
				return time.Unix(0, 0)
			}
			defaultTicket = &Ticket{
				Uid:        "myuser",
				Cip:        "127.0.0.1",
				Validuntil: time.Unix(1, 0),
				Tokens:     []string{"token1", "token2"},
			}
		})
		Context("VerifyTicket", func() {
			It("Should complain about signature when signature isn't valid", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTAuthCookieName: "fake",
					TKTAuthHeader:     []string{"fake"},
				})
				Expect(err).ToNot(HaveOccurred())
				defaultTicket.Sig = "mysignature"

				err = auth.VerifyTicket(defaultTicket, "")
				Expect(err).Should(HaveOccurred())
				_, isErrSigNotValid := err.(ErrSigNotValid)
				Expect(isErrSigNotValid).Should(BeTrue())
			})
			It("Should use either rsa or dsa verify when TKTAuthDigest is not set", func() {
				authRsa, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTCheckIpEnabled: false,
					TKTAuthToken:      []string{"token1"},
					TKTAuthCookieName: "fake",
					TKTAuthHeader:     []string{"fake"},
				})
				Expect(err).ToNot(HaveOccurred())
				authDsa, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyDsa,
					TKTCheckIpEnabled: false,
					TKTAuthToken:      []string{"token1"},
					TKTAuthCookieName: "fake",
					TKTAuthHeader:     []string{"fake"},
				})

				Expect(err).ToNot(HaveOccurred())
				defaultTicket.Sig = sha1Sig
				err = authRsa.VerifyTicket(defaultTicket, "")
				Expect(err).ShouldNot(HaveOccurred())

				defaultTicket.Sig = dss1Sig
				err = authDsa.VerifyTicket(defaultTicket, "")
				Expect(err).ShouldNot(HaveOccurred())
			})
			It("should complain about token not found when user doesn't have the requested token", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTCheckIpEnabled: false,
					TKTAuthToken:      []string{"requiredToken"},
					TKTAuthCookieName: "fake",
					TKTAuthHeader:     []string{"fake"},
				})
				Expect(err).ToNot(HaveOccurred())
				defaultTicket.Sig = sha1Sig

				err = auth.VerifyTicket(defaultTicket, "")
				Expect(err).Should(HaveOccurred())
				_, isType := err.(ErrNoValidToken)
				Expect(isType).Should(BeTrue())
			})
			It("should complain about ip if user doesn't have the ip inside the ticket", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTCheckIpEnabled: true,
					TKTAuthToken:      []string{"token1"},
					TKTAuthCookieName: "fake",
					TKTAuthHeader:     []string{"fake"},
				})
				Expect(err).ToNot(HaveOccurred())
				defaultTicket.Sig = sha1Sig

				err = auth.VerifyTicket(defaultTicket, "fakeIP")
				Expect(err).Should(HaveOccurred())
				_, isType := err.(ErrWrongIp)
				Expect(isType).Should(BeTrue())
			})
			It("should complain about expiration if current time is higher than expiration time", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTCheckIpEnabled: false,
					TKTAuthToken:      []string{"token1"},
					TKTAuthCookieName: "fake",
					TKTAuthHeader:     []string{"fake"},
				})
				Expect(err).ToNot(HaveOccurred())
				defaultTicket.Sig = sha1Sig
				TimeNowFunc = func() time.Time {
					return time.Unix(2, 0)
				}
				err = auth.VerifyTicket(defaultTicket, "")
				Expect(err).Should(HaveOccurred())
				_, isType := err.(ErrValidationExpired)
				Expect(isType).Should(BeTrue())
			})
			It("should return no error when all is valid", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTCheckIpEnabled: true,
					TKTAuthToken:      []string{"token1"},
					TKTAuthCookieName: "fake",
					TKTAuthHeader:     []string{"fake"},
				})
				Expect(err).ToNot(HaveOccurred())

				defaultTicket.Sig = sha1Sig
				err = auth.VerifyTicket(defaultTicket, "127.0.0.1")
				Expect(err).ShouldNot(HaveOccurred())
			})
		})
		Context("VerifyTicket", func() {
			It("should return no error and a ticket when all is valid", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTCheckIpEnabled: true,
					TKTAuthRequireSSL: true,
					TKTAuthCookieName: "pubtkt",
					TKTAuthToken:      []string{"token1"},
					TKTAuthHeader:     []string{"cookie"},
				})
				Expect(err).ToNot(HaveOccurred())

				defaultTicket.Sig = sha1Sig
				req, _ := http.NewRequest("GET", "http://local.com", nil)
				req.TLS = &tls.ConnectionState{}
				req.RemoteAddr = "127.0.0.1:52332"
				req.AddCookie(&http.Cookie{Name: "pubtkt", Value: url.QueryEscape(defaultTicket.String())})

				ticket, err := auth.VerifyFromRequest(req)
				Expect(err).ShouldNot(HaveOccurred())

				defaultTicket.RawData = "uid=myuser;cip=127.0.0.1;validuntil=1;tokens=token1,token2"
				Expect(ticket).Should(Equal(defaultTicket))

			})
			It("should return no error and a ticket when all is valid and ip in x-forwarded-for is correct", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:     pubKeyRsa,
					TKTCheckIpEnabled:    true,
					TKTCheckXForwardedIp: true,
					TKTAuthRequireSSL:    true,
					TKTAuthCookieName:    "pubtkt",
					TKTAuthToken:         []string{"token1"},
					TKTAuthHeader:        []string{"cookie"},
				})
				Expect(err).ToNot(HaveOccurred())
				defaultTicket.Sig = sha1Sig

				req, _ := http.NewRequest("GET", "http://local.com", nil)
				req.TLS = &tls.ConnectionState{}
				req.Header.Set("X-Forwarded-For", "127.0.0.1:6060")
				req.AddCookie(&http.Cookie{Name: "pubtkt", Value: url.QueryEscape(defaultTicket.String())})

				ticket, err := auth.VerifyFromRequest(req)
				Expect(err).ShouldNot(HaveOccurred())

				defaultTicket.RawData = "uid=myuser;cip=127.0.0.1;validuntil=1;tokens=token1,token2"
				Expect(ticket).Should(Equal(defaultTicket))

			})
			It("should complain if ssl is required and request is not tls", func() {
				auth, _ := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTCheckIpEnabled: false,
					TKTAuthRequireSSL: true,
					TKTAuthToken:      []string{"token1"},
					TKTAuthCookieName: "fake",
					TKTAuthHeader:     []string{"fake"},
				})
				defaultTicket.Sig = sha1Sig
				req, _ := http.NewRequest("GET", "http://local.com", nil)
				_, err := auth.VerifyFromRequest(req)
				Expect(err).Should(HaveOccurred())
				_, isType := err.(ErrNoSSl)
				Expect(isType).Should(BeTrue())
			})
			It("should complain about ip if request remote address doesn't have the ip inside the ticket ", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:  pubKeyRsa,
					TKTCheckIpEnabled: true,
					TKTAuthRequireSSL: false,
					TKTAuthToken:      []string{"token1"},
					TKTAuthHeader:     []string{"cookie"},
					TKTAuthCookieName: "pubtkt",
				})
				Expect(err).ToNot(HaveOccurred())
				defaultTicket.Sig = sha1Sig
				req, _ := http.NewRequest("GET", "http://local.com", nil)
				req.RemoteAddr = "fakeip:52332"
				req.AddCookie(&http.Cookie{Name: "pubtkt", Value: url.QueryEscape(defaultTicket.String())})

				_, err = auth.VerifyFromRequest(req)
				Expect(err).Should(HaveOccurred())
				_, isType := err.(ErrWrongIp)
				Expect(isType).Should(BeTrue())
			})
			It("should complain about ip if request header x-forwarded-for doesn't have the ip inside the ticket ", func() {
				auth, err := NewAuthPubTkt(AuthPubTktOptions{
					TKTAuthPublicKey:     pubKeyRsa,
					TKTCheckIpEnabled:    true,
					TKTCheckXForwardedIp: true,
					TKTAuthRequireSSL:    false,
					TKTAuthToken:         []string{"token1"},
					TKTAuthHeader:        []string{"cookie"},
					TKTAuthCookieName:    "pubtkt",
				})
				Expect(err).ToNot(HaveOccurred())
				defaultTicket.Sig = sha1Sig
				req, _ := http.NewRequest("GET", "http://local.com", nil)
				req.Header.Set("X-Forwarded-For", "fakeip:52332")
				req.AddCookie(&http.Cookie{Name: "pubtkt", Value: url.QueryEscape(defaultTicket.String())})

				_, err = auth.VerifyFromRequest(req)
				Expect(err).Should(HaveOccurred())
				_, isType := err.(ErrWrongIp)
				Expect(isType).Should(BeTrue())
			})
		})
	})
})
