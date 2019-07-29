package pubtkt_test

import (
	. "github.com/orange-cloudfoundry/go-auth-pubtkt"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hash", func() {
	var expectedValue = "data"
	var passPhraseEcb = "mysuperpassphrase"
	var encEcbValueSalted = "U2FsdGVkX19p0Mg7tyI6JtMziQ/siQtwHIFj7pm4U2o=" // equals to data
	var encCbcValueSalted = "U2FsdGVkX1+EqZns6jnWZVbZqE7e+ItxcW6MmM/UjzU=" // equals to data
	var encEcbValueNotSalted = "tmmFinI/1PndotM+LvQCNQ=="                  // equals to data
	var encCbcValueNotSalted = "KaVFD+0+w6ky1o/dvOY86Q=="                  // equals to data
	Context("DecryptString", func() {
		Context("With ecb encryption", func() {
			It("should decode correctly when it's salted", func() {
				result, err := NewOpenSSL().DecryptString(passPhraseEcb, encEcbValueSalted, MethodEcb)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(result)).Should(Equal(expectedValue))
			})
			It("should decode correctly when it's not salted", func() {
				result, err := NewOpenSSL().DecryptString(passPhraseEcb, encEcbValueNotSalted, MethodEcb)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(result)).Should(Equal(expectedValue))
			})
		})
		Context("With cbc encryption", func() {
			It("should decode correctly when it's salted", func() {
				result, err := NewOpenSSL().DecryptString(passPhraseEcb, encCbcValueSalted, MethodCbc)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(result)).Should(Equal(expectedValue))
			})
			It("should decode correctly when it's not salted", func() {
				result, err := NewOpenSSL().DecryptString(passPhraseEcb, encCbcValueNotSalted, MethodCbc)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(result)).Should(Equal(expectedValue))
			})
		})
	})
	Context("EncrypString", func() {
		Context("With ecb encryption", func() {
			It("should encode correctly", func() {
				crypted, err := NewOpenSSL().EncryptString(passPhraseEcb, "data", MethodEcb)
				Expect(err).ToNot(HaveOccurred())

				result, err := NewOpenSSL().DecryptString(passPhraseEcb, string(crypted), MethodEcb)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(result)).Should(Equal(expectedValue))
			})
		})
		Context("With cbc encryption", func() {
			It("should encode correctly", func() {
				crypted, err := NewOpenSSL().EncryptString(passPhraseEcb, "data", MethodCbc)
				Expect(err).ToNot(HaveOccurred())

				result, err := NewOpenSSL().DecryptString(passPhraseEcb, string(crypted), MethodCbc)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(result)).Should(Equal(expectedValue))
			})
		})
	})
	Context("BauthDecrypt", func() {
		It("Should decrypt bauth from aes-128-cbc", func() {
			key := "AZERTYUIOPQSDFGH"
			cryptedBauth := "6EAv9/i8HmAN3yr681s8OsNXJ4Xw0Qe70taHuUNvV7k=" // == mydata

			res, err := BauthDecrypt(cryptedBauth, key)
			Expect(err).ToNot(HaveOccurred())
			Expect(res).Should(Equal("mydata"))
		})
	})

	Context("BauthEncryp", func() {
		It("Should encrypt bauth from aes-128-cbc", func() {
			key := "AZERTYUIOPQSDFGH"

			crypted, err := BauthEncrypt("mydata", key)
			Expect(err).ToNot(HaveOccurred())

			res, err := BauthDecrypt(crypted, key)
			Expect(err).ToNot(HaveOccurred())
			Expect(res).Should(Equal("mydata"))
		})
	})
})
