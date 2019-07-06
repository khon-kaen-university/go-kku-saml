package kkusaml

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"github.com/russellhaering/goxmldsig"
)

var (
	// SAMLSP for SAML service provider
	SAMLSP *saml2.SAMLServiceProvider
)

// NewSAML creates a new SAML service provider.
func NewSAML(idpMetadataURL string, issuerURL string, audienceURL string, callbackURL string, spCertPath string, spPrivKeyPath string) (err error) {
	// Get IDP metadata
	res, err := http.Get(idpMetadataURL)
	if err != nil {
		return err
	}

	// Read metadata body
	rawMetadata, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	// Extract IDP metadata
	metadata := types.EntityDescriptor{}
	err = xml.Unmarshal(rawMetadata, &metadata)
	if err != nil {
		return err
	}

	// Create certificate storage
	certStore := dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{},
	}

	// Add IDP certificate into store
	for _, kd := range metadata.IDPSSODescriptor.KeyDescriptors {
		for idx, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			if xcert.Data == "" {
				return fmt.Errorf("NewSAML: metadata certificate(%d) must not be empty", idx)
			}
			certData, err := base64.StdEncoding.DecodeString(xcert.Data)
			if err != nil {
				return err
			}

			idpCert, err := x509.ParseCertificate(certData)
			if err != nil {
				return err
			}

			certStore.Roots = append(certStore.Roots, idpCert)
		}
	}

	// Service Provider x509 certificate
	spStore := LoadKeyStore(spCertPath, spPrivKeyPath)

	// Create Service Provider
	sp := &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      metadata.IDPSSODescriptor.SingleSignOnServices[0].Location,
		IdentityProviderIssuer:      issuerURL,
		ServiceProviderIssuer:       audienceURL,
		AssertionConsumerServiceURL: callbackURL,
		SignAuthnRequests:           true,
		AudienceURI:                 audienceURL,
		IDPCertificateStore:         &certStore,
		SPKeyStore:                  spStore,
	}

	// Set pointer
	SAMLSP = sp

	// Return error if occur
	return err
}
