// Check OCSP revocation status.
// 1. Get stapled response from tls conn.OCSPResponse()
//      and check using ocsp.ParseResponse()
// 2. If there is no stapled response, check manually:
//      a. Get issuer and server x509 certs
//      b. Get OCSP url from the server's x509 Certificate.OCSPServer
//      c. Use ocsp.CreateRequest() to create a request
//      d. Send POST request to {url} with raw ocsp request
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/ocsp"
)

var (
	destURL    = flag.String("url", "", "url to check")
	issuerPath = flag.String("issuerpem", "", "issuer cert (PEM)")
	issuerURL  = flag.String("issuerurl", "", "url of issuer cert (PEM)")
	certPath   = flag.String("certpem", "", "cert (PEM) to check")
	certURL    = flag.String("certurl", "", "url of cert (PEM) to check")
	ocspURL    = flag.String("ocspurl", "", "url of OCSP responder")

	authorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	aiaOCSP             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	aiaIssuer           = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

func decodeAIA(ext []byte) (string, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(ext, &seq)
	if err != nil {
		return "", fmt.Errorf("Error unmarshaling %s", err)
	} else if len(rest) != 0 {
		return "", fmt.Errorf("x509: trailing data after X.509 extension")
	}

	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return "", asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes

	for len(rest) > 0 {
		var inside asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &inside)
		if err != nil {
			return "", fmt.Errorf("Error unmarshaling %s", err)
		}

		if !inside.IsCompound || inside.Tag != 16 || inside.Class != 0 {
			return "", asn1.StructuralError{Msg: "bad SAN sequence"}
		}

		var oidValue asn1.ObjectIdentifier
		body, err := asn1.Unmarshal(inside.Bytes, &oidValue)
		if err != nil {
			return "", fmt.Errorf("Error unmarshaling %s", err)
		}

		var extensionData asn1.RawValue
		rest, err := asn1.Unmarshal(body, &extensionData)
		if err != nil {
			return "", fmt.Errorf("Error unmarshaling %s", err)
		} else if len(rest) != 0 {
			return "", fmt.Errorf("x509: trailing data after AIA extension")
		}

		if oidValue.Equal(aiaIssuer) {
			switch extensionData.Tag {
			case 6:
				return string(extensionData.Bytes), nil
			default:
				return "", fmt.Errorf("Unknown type for AIA Issuer extension: %+v", extensionData)
			}
		}

	}

	// No AIA Issuer extension values
	return "", nil
}

func grabIssuerCert(connState *tls.ConnectionState) *x509.Certificate {
	return connState.VerifiedChains[0][1]
}

func grabServerCert(connState *tls.ConnectionState) *x509.Certificate {
	return connState.VerifiedChains[0][0]
}

func manualCheck(ee *x509.Certificate, issuer *x509.Certificate) error {
	if *ocspURL == "" {
		*ocspURL = ee.OCSPServer[0]
	}
	log.Printf("Server: %v\n", ee.Subject.CommonName)
	log.Printf("Issuer: %v\n", issuer.Subject.CommonName)
	log.Printf("OCSP URL: %v\n", *ocspURL)

	ocspReq, err := ocsp.CreateRequest(ee, issuer, nil)
	if err != nil {
		return fmt.Errorf("error creating ocsp request: %v", err)
	}
	body := bytes.NewReader(ocspReq)
	req, err := http.NewRequest("POST", *ocspURL, body)
	if err != nil {
		return fmt.Errorf("error creating http post request: %v", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending post request: %v", err)
	}

	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)
	return parseResponse(buf.Bytes(), issuer)
}

func parseResponse(response []byte, issuer *x509.Certificate) error {
	resp, err := ocsp.ParseResponse(response, issuer)
	if err != nil {
		return fmt.Errorf("error parsing response: %v", err)
	}
	if resp.Status == ocsp.Good {
		log.Println("Certificate Status Good.")
	} else if resp.Status == ocsp.Unknown {
		log.Println("Certificate Status Unknown")
	} else {
		log.Println("Certificate Status Revoked")
	}
	return nil
}

func stapledCheck(ee *x509.Certificate, issuer *x509.Certificate, staple []byte) error {
	log.Printf("Server: %v\n", ee.Subject.CommonName)
	log.Printf("Issuer: %v\n", issuer.Subject.CommonName)

	return parseResponse(staple, issuer)
}

func processURL() error {
	resp, err := http.Get(*destURL)
	if err != nil {
		return err
	}
	connState := resp.TLS
	if connState == nil {
		return fmt.Errorf("no connection state")
	}

	server := grabServerCert(connState)
	issuer := grabIssuerCert(connState)
	staple := connState.OCSPResponse

	if staple == nil {
		// manually check revocation
		log.Println("manual check")
		return manualCheck(server, issuer)
	}

	// parse the ocsp response
	log.Println("stapled check")
	return stapledCheck(server, issuer, staple)
}

func loadCertFromPEM(pemdata []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemdata)
	if block == nil {
		log.Fatalf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: %v\n", err)
	}

	return cert, err
}

func loadCertFromPEMFile(pathname *string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(*pathname)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}

	return loadCertFromPEM([]byte(certPEM))
}

func fetchCertFromPEMURL(url *string) (*x509.Certificate, error) {
	resp, err := http.Get(*url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	certBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("failed to read response body")
		return nil, err
	}

	return loadCertFromPEM([]byte(certBytes))
}

func fetchCertFromAIAURL(cert *x509.Certificate) (*x509.Certificate, error) {
	var aiaURL *string
	var err error

	for _, ext := range cert.Extensions {
		if ext.Id.Equal(authorityInfoAccess) {
			url, err := decodeAIA(ext.Value)
			if err != nil {
				return nil, err
			}

			if len(url) > 0 {
				aiaURL = &url
			}
		}
	}

	if aiaURL == nil {
		return nil, fmt.Errorf("No AIA url, and previous error was %s", err)
	}

	log.Printf("Fetching issuer certificate from %s", *aiaURL)
	return fetchCertFromPEMURL(aiaURL)
}

func main() {
	flag.Parse()

	var err error

	if *destURL != "" {
		if !strings.HasPrefix(*destURL, "https") {
			log.Fatalf("must provide a https url\n")
		}
		err := processURL()
		if err != nil {
			log.Fatalf("Error processing URL: %v\n", err)
		}

	} else if *certPath != "" || *certURL != "" {
		var issuer *x509.Certificate
		var cert *x509.Certificate
		if *certPath != "" {
			cert, err = loadCertFromPEMFile(certPath)
			if err != nil {
				log.Fatalf("Error processing file: %v\n", err)
			}
		} else if *certURL != "" {
			cert, err = fetchCertFromPEMURL(certURL)
			if err != nil {
				log.Fatalf("Error processing URL: %v\n", err)
			}
		}

		if *issuerPath != "" {
			issuer, err = loadCertFromPEMFile(issuerPath)
			if err != nil {
				log.Fatalf("Error processing file: %v\n", err)
			}
		} else if *issuerURL != "" {
			issuer, err = fetchCertFromPEMURL(issuerURL)
			if err != nil {
				log.Fatalf("Error processing URL: %v\n", err)
			}
		} else {
			issuer, err = fetchCertFromAIAURL(cert)
			if err != nil {
				log.Fatalf("Error processing AIA URL: %v\n", err)
			}
		}

		err := manualCheck(cert, issuer)
		if err != nil {
			log.Fatalf("Error performing manual check: %v\n", err)
		}

	} else {
		log.Fatalf("must provide a url or cert\n")
	}
}
