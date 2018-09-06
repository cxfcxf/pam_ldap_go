# pam_ldap_go

please be note, this will only work with onelogin's vldap or

any ldap server that uses tls but not need to verify cert

this is very useful since it will bind authuser directly for auth

without requiring binduser/bindpass for search then bind authuser 

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
