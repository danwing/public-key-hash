---
title: "Public Key Hash for Local Domains"
abbrev: "Public Key Hash for Local Domains"
category: std

docname: draft-wing-settle-public-key-hash-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
#  group: WG
#  type: Working Group
#  mail: WG@example.com
#  arch: https://example.com/WG
  github: "danwing/public-key-hash"
  latest: "https://danwing.github.io/public-key-hash/draft-wing-settle-public-key-hash.html"

author:
 -
    fullname: Martin Thomson
    organization: Mozilla
    email: mt@lowentropy.net
 -
    ins: D. Wing
    name: Dan Wing
    organization: Cloud Software Group Holdings, Inc.
    abbrev: Cloud Software Group
    email: danwing@gmail.com
    role: editor

normative:

informative:


--- abstract

This specification eliminates security warnings when connecting to local domains
using TLS.  Servers use a long hostname which encodes their public key that
the client validates against the public key presented in the TLS handshake.

--- middle

# Introduction

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Operation

## Server Operation

A server running on a local network (see {{unique}}) uses a unique host
name that includes a hash of its public key.  This unique name is encoded as
described in {{encoding}}.

The server MAY also advertise its unique name using {{?DNS-SD=RFC6763}}.  It
MAY also advertise its short name as described in {{short}}.

## Client Operation

When clients connect to such a local domain name or IP address
({{local}}) using TLS they examine if the domain name starts with a
registered hash identifier in the second label and if the rest of that
label consists of an appropriate-length encoded hash. If those
conditions apply, the client MAY send a TLS ClientHello with the Raw
Public Key extension {{?RFC7250}}. When the client receives the
server's raw public key or certificate, the client checks if the hash
matches the public key received in the TLS ServerHello. If they match,
the client authenticates the TLS connection. If they do not match, the
client behavior falls back to the client's normal handling of the
presented TLS raw public key or certificate (which may well be valid).


# Unique Host Names {#unique}

Web browsers and other application clients store per-host state using
the host name, including cached form data such as passwords,
integrated and 3rd party password managers, cookies, and other data.
When a name collision occurs (e.g., the same printer.local name on
two different networks) the client cannot recognize a different host
is being encountered.  While it is possible to extend all of these
clients to extend their index to include the server's public key, this
seems to lack business justification for the engineering effort to
solely improve the user experience (short name, {{short}}) on local networks.

A unique name can be created by embedding the hash of the public
key into the name itself.  This achieves uniqueness and is also
used by the client to validate the server's public key {{validation}}.
Details on encoding are in {{encoding}}.

To ease clients connecting to these long names, servers SHOULD
advertise their long names on the local network {{?DNS-SD=RFC6763}}.


# Short Host Names {#short}

Long host names containing encoded public keys are awkward for users. This
section describes how short names can also be advertised by servers and
securely validated by clients, so that the short name is presented to
users while the long name is used to actually connect.

The server advertises both its (long) unique name and its short
nickname using {{!DNS-SD=RFC6763}}.  The client connects to the long
name and performs a full TLS handshake and validation
({{validation}}).  The client then connects to the short nickname and
performs a full TLS handshake. If the same public key was presented by
both TLS connections, the client SHOULD present both the
long name and short name to the user.

The client need only look for matching short name and unique name
within the same TLD domain name (that is, if a unique name is advertised
with a ".local" domain, the client does not need to look for its
accompanying short name within ".internal").

To avoid the problems described in {{unique}}, the TLS data connection
to the printer MUST always use the long name.  Thus, if the client has
validated the short name as described above and a user attempts to
connect to printer.local (by typing or by some other user
interaction), the client MUST connect to the unique name.  The TLS
connection to the short name MUST NOT be used by the client after the
TLS handshake completes and the server MUST terminate the TLS
handshake after the Finished message by sending TLS close_notify.


# Raw Public Keys {#rpk}

Todo:  rewrite this section

Certificates are complicated for most people. They also have an
expiration date.  This system uses a public key for the lifetime
of the device, which is hopefully years. A certificate is not
appropriate; a raw public key is more approporiate.

# Validation {#validation}

The client connects to a unique hostname and sends a TLS ClientHello.
As the client only needs the raw public key, the request MAY include
a request for a raw public key {{!RFC7250}}.  The client parses
the returned certificate or raw public key to extract the public key
and compare its hash with the hash contained in the hostname. If
they match, the TLS session continues. If they do not match, the
client might warn the user (as is common today) or simply abandon
the TLS connection.

If a certificate is returned both its 'NotBefore' and 'NotAfter' dates
are ignored for purposes of this specification.

# Encoding Details {#encoding}

The general format is hostname, a period, a digit indicating the hash
algorithm, and then the hash of the server's public key.  The binary
hash output is base32 encoded ({{Section 6 of !RFC4648}}) without
trailing "=" padding.  Currently only SHA256 hash is defined with the
value "0" ({{iana}}).  While base32 encoding is specified as uppercase,
implementations should treat uppercase, lowercase, and mixed case
the same.

~~~~ abnf
friendly-name = 1*63(ALPHA / DIGIT / "-")

hash-algorithm = DIGIT   ; 0=SHA256

base32-digits = "2" / "3" / "4" / "5" / "6" / "7"

hash = 1*62(/ ALPHA / base32-digits )
     ; 62+1 octet limit from RFC1035

encoded-hostname = friendly-name "."
                   hash-algorithm
                   hash
~~~~~
{: artwork-align="center" artwork-name="encoding"}

An example encoding is shown in {{test-encoding}}.


# Identifying Servers as Local {#local}

This section defines the domain names and IP addresses considered
"local" which clients MAY use with this specification.  Other domain
names and other IP addresses SHOULD NOT be used with this
specification.

## Local Domain Names

The following domain name suffixes are considered "local":

* ".local" (from {{?mDNS=RFC6762}})
* ".home-arpa" (from {{?Homenet=RFC8375}})
* ".internal" (from {{?I-D.davies-internal-tld}})
* both ".localhost" and "localhost" (Section 6.3 of {{?RFC6761}})

## Local IP Addresses

Additionally, if any host resolves to a local IP address and
connection is made to that address, those are also considered
"local":

* 10/8, 172.16/12, and 192.168/16 (from {{?RFC1918}})
* 169.254/16 and fe80::/10 (from {{?RFC3927}} and {{?RFC4291}})
* fc00::/7 (from {{?RFC4193}})
* 127/8 and ::1/128 (from {{?RFC990}} and {{?RFC4291}})

# Incremental Deployment

Where a server's hostname can be configured, a motivated network
administrator can configure server hostnames to comply with this
specification to provide immediate value to supporting clients.

# Security Considerations

TODO: write more on security considerations

Because the server's public key is encoded into its domain name,
changing the public key would also change its domain name -- thus, its
identity as known by client password managers and other configurations
in clients (e.g., printer, SMB share, etc.).  As such an identity
change is extremely disruptive, it needs to be avoided.  This means
the public/private key pair on a server needs to stay static.  The
tradeoff is servers are vulnerable to their private keys being stolen
and an active attacker intercepting traffic to that server.  The
alternatives are to continue using unencrypted communication to local
servers, which is vulnerable to passive attack, or to condition users
to validate self-signed certificates for local servers.




# IANA Considerations {#iana}

New registry for hash type, 0=SHA256.  Extensions via IETF Action.


--- back

# Discussion Points

## DTLS

This should work for DTLS, as well?


# Test Encoding {#test-encoding}

Server with private key in PEM format is:

~~~~~
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCOkTU8TOKW/IZ6
whhyhg+1I4u0jm019z4SVUKAwKyOtFPtoEvRGPdKYUoLaPZmVyN/VTYlubVn7dE8
IYpibwkDhs38DKmyo0vdWjUaopQOaygtLB+PZ12l/XaSCE1cWsl45ShUvktcVR/D
DKwv7DWEIZrRTLKy6M+8Ne4x++kKXmwbSj8WsNQ4kU4uFhS+JXHXToZvhvoQLkTs
486XXPn4SJPLyTN62b6KHTLM1vb7RY4i4U7N6hS1UWe7bIxZNZ0vnf4vZ7A6SR7W
nM31DoaW5XCBH7CL56MSdn7dmuksRimfNmnsEmvBXZmuQMHnUZghBLMHPC9xmHhT
8q3pSY5jAgMBAAECggEANiAY1vDVob7zi01/HJObCQkatAzSl4drUGiAHAOKP49k
wbV2s0bIM7vl8ZkC2u3AM0p1iTMNFQzrv+l38VD4WhdmwodIMeLfHYVu3dLVZPf3
w9aZkMcMfcVRq7VtMV/iV3ygqDOqxr4mldWM1ZDW7HgZn9Z/jX7nxyuuZ9mcquuH
Brl8pcUba7666jcz+F9NNjXTPCwfm7ihCPkTeYr1NflQGTR5PJ+D5dywb53iulm1
ZTk2zBXJMujbIyTL0p+MqdEKXci7oQJqf7bQsxsO2ZUD24CmzYldsE6vmYUFxJpw
ZbYzO/a/Mv0mXQhcUTWKkJkU78QT2Us7SuSL+IPGSQKBgQDC5iRKtlYulUgxV9gu
TmX30R0W7R0nnsEjolNAqUwcIoUMHk8ODXEsp7jVOSFMJhHRMXL+VKYiBsiIV7vk
GlTbLRP34HgK54auRF6PTxBfNAkF+FQxl2mzWxj7wi5mg0g+tCJTLereUXULz8+r
h5Vqp4BCjcoumlyY0xlLtbr9/wKBgQC7Qx2Lb70XCL5eivdokMh2lRint9cfxC2W
fJ6QOnJgsN9XIQGTUAk3cLvmrKg3UOmJXXq+Q6djVB/3Op3+TFzsGS2ORMel9r6o
kAHYG/qdairlW9uTDsnwUP8UtE0lidhSXLGIAy71eMDbDg/c/yyrWTvysXf5kAiJ
CzTnyvY3nQKBgBt+Va5IbH3jxyxWxQM7Qf0kfaMHTe6R4ZMCShY8C6WIZRZhjCti
UA3JlzRU+9J/KFJHVH52OH1iUZWSMsopwMCuaju0aZq4MHKS6Hf04k1bzM4Pyui4
AEwx1KNnMB579IwL4y+ysYgtG4LQDO6YkMZb3KcG03ehhOB2HwJkH33HAoGATOw3
8bQ3v4OG970r/lcjEZsTYqnhA5qJg3yzgdmQbGmbhOX5CLNi5dQ4S3x3KSnilNvC
dO/DjcjbzKnWhsSFkzKQhRV50ZH3JbTqHQT5QLqA3nCKVPFJQJ90+ONLoXTrWIHd
J1rvakRtLE6tc4GartRcDMib2PcymmDxHZpA4/0CgYEAs0XF1G0gmnef8oEYuwZT
c+vr4wnD7YCP1h8nsNSgRHLk1e7k727iHGvruX3qrKsY26RHKi2+i1P6A39I4F5s
3Dme4HGXTyoc/qKp+/GAx5XYVG4c3Z3sdBejkpkhPTSlsSsDOHbjaiFV1zCyEdg5
fOPfIBX8uLc3UtOm0+Gn1IQ=
-----END PRIVATE KEY-----
~~~~~

and public key in PEM format is:

~~~~~
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjpE1PEzilvyGesIYcoYP
tSOLtI5tNfc+ElVCgMCsjrRT7aBL0Rj3SmFKC2j2Zlcjf1U2Jbm1Z+3RPCGKYm8J
A4bN/AypsqNL3Vo1GqKUDmsoLSwfj2ddpf12kghNXFrJeOUoVL5LXFUfwwysL+w1
hCGa0UyysujPvDXuMfvpCl5sG0o/FrDUOJFOLhYUviVx106Gb4b6EC5E7OPOl1z5
+EiTy8kzetm+ih0yzNb2+0WOIuFOzeoUtVFnu2yMWTWdL53+L2ewOkke1pzN9Q6G
luVwgR+wi+ejEnZ+3ZrpLEYpnzZp7BJrwV2ZrkDB51GYIQSzBzwvcZh4U/Kt6UmO
YwIDAQAB
-----END PUBLIC KEY-----
~~~~~

Using the binary format (DER) and hashed using SHA256 gives this
hex value:

~~~~~
21ebc0d00e98e3cb289738e2c091e532c4ad8240e0365b22067a1449693e5a18
~~~~~

Converting that hex value to binary and base32 encoded (without
trailing "=") gives:

~~~~~
EHV4BUAOTDR4WKEXHDRMBEPFGLCK3ASA4A3FWIQGPIKES2J6LIMA
~~~~~

After the hash algorithm identification digit (0 for SHA512/256) is
prefixed to that base64url, resulting in:

~~~~~
0EHV4BUAOTDR4WKEXHDRMBEPFGLCK3ASA4A3FWIQGPIKES2J6LIMA
~~~~~

Finally, if this is a printer named "printer" advertised using
".local", the full FQDN for its unique name would be:

~~~~~
printer.0EHV4BUAOTDR4WKEXHDRMBEPFGLCK3ASA4A3FWIQGPIKES2J6LIMA.local
~~~~~

and the full FQDN for its short name would be "printer.local".


# Acknowledgments
{:numbered="false"}

This Internet Draft started as a document published by Martin
Thomson in 2007.
