package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/zro/pam"
	ldap "gopkg.in/ldap.v2"
	yaml "gopkg.in/yaml.v2"
)

var pl pamLdap

type pamLdap struct {
	Insecure       bool   `yaml:"Insecure"`
	LoginAttr      string `yaml:"LoginAttr"`
	ObjectClass    string `yaml:"ObjectClass"`
	Remote         string `yaml:"Remote"`
	Port           string `yaml:"Port"`
	SearchBase     string `yaml:"SearchBase"`
	DirectBindAuth bool   `yaml:"DirectBindAuth"`
	BindDN         string `yaml:"BindDN,omitempty"`
	BindPW         string `yaml:"BindPW,omitempty"`
}

func parseConfig(file string, pl *pamLdap) error {
	f, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(f, &pl)
	if err != nil {
		return err
	}
	return nil
}

func ldapAuth(pl *pamLdap, authuser, authtoken string) error {
	remote := pl.Remote + ":" + pl.Port

	tlsConfig := &tls.Config{
		InsecureSkipVerify: pl.Insecure,
		ServerName:         pl.Remote,
	}

	l, err := ldap.DialTLS("tcp", remote, tlsConfig)
	if err != nil {
		return err
	}

	defer l.Close()

	if pl.DirectBindAuth {
		// this shortcut the search and try to bind authuser directly
		user := fmt.Sprintf("%s=%s,%s", pl.LoginAttr, authuser, pl.SearchBase)

		// bind auth user
		err = l.Bind(user, authtoken)
	} else {
		// normal binding when DirectBindAuth is false
		// bind search user -> search -> bind auth user
		err = l.Bind(pl.BindDN, pl.BindPW)
		if err != nil {
			return err
		}

		filter := fmt.Sprintf("(&(objectClass=%s)(%s=%s))", pl.ObjectClass, pl.LoginAttr, authuser)

		searchRequest := ldap.NewSearchRequest(
			pl.SearchBase,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			filter,
			[]string{"dn"},
			nil,
		)

		sr, err := l.Search(searchRequest)
		if err != nil {
			return err
		}

		if len(sr.Entries) != 1 {
			return errors.New("User does not exist or too many entries returned")
		}

		userdn := sr.Entries[0].DN

		err = l.Bind(userdn, authtoken)
		if err != nil {
			return err
		}
	}

	return err
}

func (pl *pamLdap) Authenticate(hdl pam.Handle, args pam.Args) pam.Value {
	// default config file
	config := "/etc/pam_ldap.yaml"

	if val, ok := args["config"]; ok {
		config = val
	}

	if _, err := os.Stat(config); os.IsNotExist(err) {
		return pam.UserUnknown
	}

	err := parseConfig(config, pl)
	if err != nil {
		return pam.UserUnknown
	}

	authuser, err := hdl.GetUser()
	if err != nil {
		return pam.UserUnknown
	}

	authtoken, err := hdl.GetItem(pam.AuthToken)
	if err != nil {
		return pam.AuthTokenError
	}

	if len(authtoken) == 0 {
		m := pam.Message{
			Style: pam.MessageEchoOff,
			Msg:   "",
		}

		response, err := hdl.Conversation(m)
		if err != nil {
			return pam.AuthError
		}
		authtoken = response[0]
	}

	err = ldapAuth(pl, authuser, authtoken)
	if err != nil {
		return pam.UserUnknown
	}

	return pam.Success
}

func (pl *pamLdap) Validate(hdl pam.Handle, args pam.Args) pam.Value {
	skipValidate := false

	if _, ok := args["skipValidate"]; ok {
		skipValidate = true
	}

	if skipValidate {
		return pam.Success
	}

	return pam.PermissionDenied
}

func (pl *pamLdap) SetCredential(hdl pam.Handle, args pam.Args) pam.Value {
	return pam.CredentialError
}

func init() {
	pam.RegisterAuthHandler(&pl)
	pam.RegisterAccountHandler(&pl)
}

func main() {
	// needed in c-shared buildmode
}
