package main

import (
	"os"
	"fmt"
	"crypto/tls"
	"io/ioutil"

	"github.com/zro/pam"
	ldap "gopkg.in/ldap.v2"
	yaml "gopkg.in/yaml.v2"
)

var pl pamLdap

type pamLdap struct {
	LoginAttr	string	`yaml:"LoginAttr"`
	Remote		string	`yaml:"Remote"`
	Port		string	`yaml:"Port"`
	SearchBase	string	`yaml:"SearchBase"`
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

func LdapAuth(pl *pamLdap, authuser, authtoken string) error {
	remote := pl.Remote + ":" + pl.Port

	l, err := ldap.DialTLS("tcp", remote, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return err
	}

	defer l.Close()

	user := fmt.Sprintf("%s=%s,%s", pl.LoginAttr, authuser, pl.SearchBase)

	// we use this user to bind for atuh
	err = l.Bind(user, authtoken)
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
	
	err = LdapAuth(pl, authuser, authtoken)
	if err != nil {
		return pam.UserUnknown
	}

	return pam.Success
}

func (pl *pamLdap) SetCredential(hdl pam.Handle, args pam.Args) pam.Value {
	return pam.CredentialError
}

func init() {
	pam.RegisterAuthHandler(&pl)
}

func main() {
	// needed in c-shared buildmode
}