# **LDAPAuthVerify**

LDAPAuthVerify is a small Flask program that allows you to verify LDAP authentication credentials. This small program can be used to verify users against an LDAP server and check if they belong to a specified group.

This program is designed to run on localhost and provide a verification service of sorts to other local services. Right now this program is being written with [Authentik LDAP Provider](https://docs.goauthentik.io/docs/providers/ldap/) in mind where the program will communicate with an Authentik LDAP Outpost.
