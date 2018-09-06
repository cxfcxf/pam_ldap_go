# pam_ldap_go
please be note, this will work with any ldap server that uses ssl/tls

the cert of ldap server will not be verified


### configure
DirectBindAuth: false/true

true:

    steps: bind -> success
false:

    steps: bind -> search -> bind -> success

toggling ture means it will bind authuser directly for auth

without requiring binduser/bindpass for search then bind authuser

toggleing false means regular binding auth process


ObjectClass/BindDN/BindPW options are only used for filtering search (DirectBindAuth=false)

### params it can take
```
auth        sufficient    pam_ldap_go.so  config=/etc/pam_ldap.yaml <-default location
```

### how to compile
```
go build -buildmode=c-shared -o /lib64/security/pam_ldap_go.so main.go
```

### License
BSD

### thanks for 
github.com/zro/pam

this is mostly helpful for writing a pam module in golang
