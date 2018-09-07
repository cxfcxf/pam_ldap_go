package main

import (
    "os"
    "fmt"
    "errors"
    "crypto/tls"
    "io/ioutil"

    "github.com/zro/pam"
    ldap "gopkg.in/ldap.v2"
    yaml "gopkg.in/yaml.v2"
)

var pl pamLdap

type pamLdap struct {
    LoginAttr       string  `yaml:"LoginAttr"`
    ObjectClass     string  `yaml:"ObjectClass"`
    Remote          string  `yaml:"Remote"`
    Port            string  `yaml:"Port"`
    SearchBase      string  `yaml:"SearchBase"`
    DirectBindAuth  bool    `yaml:"DirectBindAuth"`
    BindDN          string  `yaml:"BindDN,omitempty"`
    BindPW          string  `yaml:"BindPW,omitempty"`
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