# LDAP-Signing
The security of Active Directory domain controllers can be significantly improved by configuring the server to reject Simple Authentication and Security Layer (SASL) LDAP binds that do not request signing (integrity verification) or to reject LDAP simple binds that are performed on a clear text (non-SSL/TLS-encrypted) connection. SASLs may include protocols such as the Negotiate, Kerberos, NTLM, and Digest protocols.

Unsigned network traffic is susceptible to replay attacks in which an intruder intercepts the authentication attempt and the issuance of a ticket. The intruder can reuse the ticket to impersonate the legitimate user. Additionally, unsigned network traffic is susceptible to man-in-the-middle (MiTM) attacks in which an intruder captures packets between the client and the server, changes the packets, and then forward them to the server. If this occurs on an Active Directory Domain Controller, an attacker can cause a server to make decisions that are based on forged requests from the LDAP client. LDAPS uses its own distinct network port to connect clients and servers. The default port for LDAP is port 389, but LDAPS uses port 636 and establishes SSL/TLS upon connecting with a client.

Channel binding tokens help make LDAP authentication over SSL/TLS more secure against man-in-the-middle attacks.

https://support.microsoft.com/en-nz/help/4520412/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows
https://support.microsoft.com/en-us/help/935834/how-to-enable-ldap-signing-in-windows-server
https://docs.microsoft.com/en-gb/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd941849(v=ws.10)
