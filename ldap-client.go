// Package ldap provides a simple ldap client to authenticate,
// retrieve basic information and groups for a user.
package ldap

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"

	"gopkg.in/ldap.v3"
)

// Client struct
type Client struct {
	Attributes         []string
	Base               string
	BindDN             string
	BindPassword       string
	GroupFilter        string // e.g. "(memberUid=%s)"
	Host               string
	ServerName         string
	UserFilter         string // e.g. "(uid=%s)"
	Conn               *ldap.Conn
	Port               int
	InsecureSkipVerify bool
	UseSSL             bool
	SkipTLS            bool
	ClientCertificates []tls.Certificate // Adding client certificates
	CACertFiles        []string          // CA cert to verify ldaps server
}

// Connect connects to the ldap backend.
func (lc *Client) Connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Host, lc.Port)
		if !lc.UseSSL {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}

			// Reconnect with TLS
			if !lc.SkipTLS {
				err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
				if err != nil {
					return err
				}
			}
		} else {
			config := &tls.Config{
				InsecureSkipVerify: lc.InsecureSkipVerify,
				ServerName:         lc.ServerName,
			}
			if lc.ClientCertificates != nil && len(lc.ClientCertificates) > 0 {
				config.Certificates = lc.ClientCertificates
			}
			if lc.CACertFiles != nil && len(lc.CACertFiles) > 0 {
				caCertPool := x509.NewCertPool()
				for _, certFile := range lc.CACertFiles {
					caCert, err := ioutil.ReadFile(certFile)
					if err != nil {
						return err
					}
					caCertPool.AppendCertsFromPEM(caCert)
				}
				config.RootCAs = caCertPool
			}
			l, err = ldap.DialTLS("tcp", address, config)
			if err != nil {
				return err
			}
		}

		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection.
func (lc *Client) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

// FindUser with specified username against the ldap backend.
func (lc *Client) FindUser(username string) (map[string][]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err := lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return nil, err
		}
	}

	attributes := append(lc.Attributes, "dn")
	// Search for the given username
	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, username),
		attributes,
		nil,
	)

	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(sr.Entries) < 1 {
		return nil, errors.New("User does not exist")
	}

	if len(sr.Entries) > 1 {
		return nil, errors.New("Too many entries returned")
	}

	userDN := sr.Entries[0].DN
	user := map[string][]string{}
	for _, attr := range lc.Attributes {
		user[attr] = sr.Entries[0].GetAttributeValues(attr)
	}
	user["dn"] = []string{userDN}

	return user, nil
}

// Authenticate authenticates the user against the ldap backend.
func (lc *Client) Authenticate(username, password string) (bool, map[string][]string, error) {
	user, err := lc.FindUser(username)
	if err != nil {
		return false, nil, err
	}

	userDN := user["dn"][0]

	// Bind as the user to verify their password
	if userDN != "" && password != "" {
		err = lc.Conn.Bind(userDN, password)
		if err != nil {
			return false, user, err
		}
	} else {
		return false, user, errors.New("no username/passowrd provided")
	}

	return true, user, nil
}

// GetGroupsOfUser returns the group for a user.
func (lc *Client) GetGroupsOfUser(username string) ([]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	defer lc.Close()

	// First bind with a read only user
	if lc.BindDN != "" && lc.BindPassword != "" {
		err = lc.Conn.Bind(lc.BindDN, lc.BindPassword)
		if err != nil {
			return []string{}, err
		}
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Base,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, username),
		[]string{"cn"}, // can it be something else than "cn"?
		nil,
	)
	sr, err := lc.Conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}
	groups := []string{}
	for _, entry := range sr.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}
	return groups, nil
}
