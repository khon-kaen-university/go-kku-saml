package kkusaml

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io/ioutil"
	"log"
	"sort"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

func scenarioIndexes(errs map[int]string, warns map[int]scenarioWarnings) (idxs []int) {
	for idx := range errs {
		idxs = append(idxs, idx)
	}
	for idx := range warns {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)
	return
}

type scenarioWarnings struct {
	InvalidTime   bool
	NotInAudience bool
}

func scenarioErrorChecker(i int, scenarioErrors map[int]string) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		if msg, ok := scenarioErrors[i]; ok && msg != "" {
			require.EqualError(t, err, msg, "Expected error message")
		} else {
			require.NoError(t, err)
		}
	}
}

func scenarioWarningChecker(i int, scenarioWarns map[int]scenarioWarnings) func(*testing.T, *saml2.WarningInfo) {
	return func(t *testing.T, warningInfo *saml2.WarningInfo) {
		expectedWarnings := scenarioWarns[i]
		require.Equal(t, expectedWarnings.InvalidTime, warningInfo.InvalidTime, "InvalidTime mismatch")
		require.Equal(t, expectedWarnings.NotInAudience, warningInfo.NotInAudience, "NotInAudience mismatch")
	}
}

func LoadXMLResponse(path string) string {
	xml, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(xml)
}

func LoadRawResponse(path string) string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	return string(data)
}

func LoadKeyStore(certPath, keyPath string) (ks dsig.TLSCertKeyStore) {
	if certBytes, err := ioutil.ReadFile(certPath); err != nil {
		log.Fatalf("%v: cannot read: %v", certPath, err)
	} else if keyBytes, err := ioutil.ReadFile(keyPath); err != nil {
		log.Fatalf("%v: cannot read: %v", keyPath, err)
	} else if cert, err := tls.X509KeyPair(certBytes, keyBytes); err != nil {
		log.Fatalf("%v/%v: cannot create key pair: %v", certPath, keyPath, err)
	} else {
		ks = dsig.TLSCertKeyStore(cert)
	}
	return
}

func LoadCertificateStore(path string) dsig.X509CertificateStore {
	encoded, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(encoded)
	if block == nil {
		panic("no certificate block found")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	return &dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{cert},
	}
}

type ProviderTestScenario struct {
	ScenarioName     string
	Response         string
	ServiceProvider  *saml2.SAMLServiceProvider
	CheckError       func(*testing.T, error)
	CheckWarningInfo func(*testing.T, *saml2.WarningInfo)
}

func getAtTime(idx int, scenarioAtTimes map[int]string) (atTime time.Time) {
	if strAtTime, ok := scenarioAtTimes[idx]; ok && strAtTime != "" {
		if atm, err := time.Parse(time.RFC3339, strAtTime); err == nil {
			return atm
		}
	}
	return // zero time
}

func spAtTime(template *saml2.SAMLServiceProvider, atTime time.Time, rawResp string) *saml2.SAMLServiceProvider {
	resp := &types.Response{}
	if rawResp == "" {
		log.Fatalf("empty rawResp")
	}
	var respBytes []byte
	var err error
	if respBytes, err = base64.StdEncoding.DecodeString(rawResp); err != nil {
		respBytes = []byte(rawResp)
	}
	if err := xml.Unmarshal(respBytes, resp); err != nil {
		log.Fatalf("cannot parse Response XML: %v", err)
	}

	var sp saml2.SAMLServiceProvider
	sp = *template // copy most fields template, we only set the clock below
	if atTime.IsZero() {
		// Prefer more official Assertion IssueInstant over Response IssueIntant
		// (Assertion will be signed, either individually or as part of Response)
		if len(resp.Assertions) > 0 && !resp.Assertions[0].IssueInstant.IsZero() {
			atTime = resp.Assertions[0].IssueInstant
		} else if !resp.IssueInstant.IsZero() {
			atTime = resp.IssueInstant
		} else {
			log.Fatalf("could not determine atTime")
		}
	}
	sp.Clock = dsig.NewFakeClock(clockwork.NewFakeClockAt(atTime))
	return &sp
}
