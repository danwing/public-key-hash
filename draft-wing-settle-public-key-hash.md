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
  group: SETTLE
  type: ""
  mail: settle@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/settle/
  github: "danwing/public-key-hash"
  latest: "https://danwing.github.io/public-key-hash/draft-wing-settle-public-key-hash.html"

author:
 -
    ins: D. Wing
    name: Dan Wing
    organization: Citrix
    abbrev: Citrix
    email: danwing@gmail.com
    country: United States of America

normative:

informative:

  secure-context:
    title: Web Platform Design Principles
    date: June 2024
    author:
      org: W3C
    target: https://w3ctag.github.io/design-principles/#secure-context

  wing-referee:
     title: A Referee to Authenticate Home Servers
     date: December 2024
     author:
       name: Dan Wing
       org: Citrix
     target: https://datatracker.ietf.org/doc/html/draft-wing-settle-referee


--- abstract
This specification eliminates security warnings when connecting to local domains
using TLS.  Servers use a unique, long hostname which encodes their public key that
the client validates against the public key presented in the TLS handshake.

--- middle

# Introduction


Browsers are progressively requiring secure origins for new
capabilities and features ({{secure-context}}). As secure origins are
only obtainable, today, with a certificate signed by a Certification
Authority trusted by the client, this leaves out devices and networks
which cannot easily obtain such certificates.  Such inability is due
to network topology (e.g., firewall), lack of domain ownership, or
complicated procedures.

This draft discusses how a client can authenticate to HTTPS servers
belonging to the local domain where the server name is a hash of the
server's public key.  By doing so, a secure origin can be established.
This avoids the need for a certificate signed by a Certification
Authority (CA) trusted by the client.  This is a relaxed way of "doing
HTTPS" for servers on the local domain.



# Unique Host Names {#unique}

Web browsers and other application clients store per-host state using
the host name, including cached form data such as passwords,
integrated and 3rd party password managers, cookies, and other data.
When a name collision occurs (e.g., the same printer.local name on
two different networks) the client cannot recognize a different host
is being encountered.  By creating a unique name, existing client
software (browsers, password managers, client libraries) can continue
storing origin-specific data for each of unique name.

A unique name is created by embedding the hash of the public key into
the name itself.  This achieves uniqueness and the encoding is also
identifiable by the client to assist its validation of the server's
public key ({{client}}).  Details on encoding the domain name are in
{{encoding}}.


# Short Host Names {#short}

Unique host names containing encoded public keys are awkward for users. This
section describes how short names can also be advertised by servers and
securely validated by clients, so that the short name is presented to
users while the unique name is used for the TLS connection.

A server already advertising its long name using {{?DNS-SD=RFC6763}}
can also advertise its short name.  The client needs to validate they
are the same server, prior to allowing the user to interact with the
short name.  The client can do this validation by making two
connections:  one connection to the long name and another to the
short name and verify they both return the same public key and that
both TLS handshakes finish successfully (proving the server has
possession of the associated private key).

> NOTE: Also to be considered is including both the unique host name
and the short host name in the SubjectAltName field of the server's
certificate. This avoids an additional {{?DNS-SD=RFC6763}} advertisement.

The client need only look for matching short name and unique name
within the same TLD domain name (that is, if a unique name is advertised
with a ".local" domain, the client does not need to look for its
accompanying short name within ".internal").

To avoid the problems described in {{unique}}, the TLS data connection
always uses the long name.  Thus, after the client has validated the
short name as described above and a user attempts to connect to the
short name (by typing or by some other user interaction), the client
instead makes a connection to the unique name.  This reduces the
integration changes within the client, as clients already separate
server-specific data based on the server name (e.g., Cookie Store API,
Credential Management API, Web Bluetooth, Storage API, Push API,
Notifications API, WebTransport API).



# Operation

## Client Operation {#client}

When clients connect to such a local domain name or IP address
({{local}}) using TLS they examine if the domain name starts with a
registered hash identifier in the second label and if the rest of that
label consists of an appropriate-length encoded hash.  If those
conditions apply, the client performs certificate validation as
described below.

Upon receipt of the server's certificate, the client validates
validates the certificate ({{?RFC9525}}, {{?RFC5280}}, and {{Section
4.3.4 of ?RFC9110}} if using HTTPS).  When performing such a
connection to a local domain, the client might avoid warning about a
self-signed certificate because the Certification Authority (CA)
signature will certainly not be signed by a trusted CA.  Rather, a
more subtle indication might be warranted for TLS connections to a
local domain, perhaps only the first time or perhaps each time.  The
client parses the returned certificate and extracts the public key and
compares its hash with the hash contained in the hostname. If they
match, the TLS session continues. If they do not match, the client
might warn the user about the certificate (as is common today) or
simply abort the TLS connection.

Protection against rogue servers on the local network is discussed
in {{rogue}}.


## Server Operation

A server running on a local network (see {{unique}}) uses a unique
host name that includes a hash of its public key.  This unique name is
encoded as described in {{encoding}}.  Existing servers might be
configurable with such a hostname, without software changes.

Oftentimes, servers operating on a local network already advertise
their presence using {{?DNS-SD=RFC6763}} and should continue doing so,
advertising their unique name that includes their public key hash
and optionally also a shorter nickname ({{short}}).


# Unique Host Name Encoding Details {#encoding}

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

An example encoding is shown in {{example-encoding}}.


# Identifying Servers as Local {#local}

This section defines the domain names and IP addresses considered
"local".

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
* 127/8 and ::1/128 (from {{Section 3.2.1.3 of ?RFC1122}} and {{?RFC4291}})


# Security Considerations

Due to operational challenges in key rotation, some servers may need to
maintain static public/private key pairs over long periods. This introduces a
tradeoff: while static keys expose servers to risks of private key compromise
and active attacks (e.g., traffic interception or server impersonation), they
still provide better security than unencrypted communication. The current approach
to use unencrypted communication to local servers—is highly vulnerable to passive
attacks. Another option, conditioning users to validate self-signed certificates,
is both error-prone and impractical.

This document proposes a new method for clients to authenticate servers within local
domains. By associating a server’s public key with its origin
(defined as the scheme, hostname, and port per RFC 6454), a client can differentiate
between servers using the same non-unique local domain name, such as printer.local.


## Rogue Servers on Local Domain {#rogue}

A client may also want to defend against rogue servers installed on
the local domain.  This requires legitimate servers be enrolled in such as
by a local domain Certification Authority (e.g.,
{{?I-D.sweet-iot-acme}}) or a local domain oracle (e.g., {{wing-referee}}).


## Public Key Hash

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

# Example Encoding {#example-encoding}

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

This draft was inspired by a document published by Martin
Thomson in 2007; however, this draft takes a different approach
by using unique names over the wire.

Other systems have also utilized public key hashes in an identifier
including Tor and Freenet's Content Hash Key.
