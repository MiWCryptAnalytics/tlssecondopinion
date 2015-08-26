# TLS Second Opinion #
by MiwCryptAnalytics

This is the source for the [TLS Second Opinion web application](https://tls2o.com).

It uses python3 and the Django Web Application framework, with some code from the great Django tutorial [Tango with Django](http://www.tangowithdjango.com)

The tlsscanner application provides a simple report on certificate and TLS connection properties.

modify tlssecondopinion/settings.py and adjust to taste.

run with:
 
`python manage.py runserver PORT`


Presently scanner.py contains most of the scanning logic, and django uses its returned values in a context dictionary to build report do.html template. Additional vulnerability scanning is to be added soon.

The generated report provides the following:

Server and Domain Details

* Server IP and Port
* GeoIP data and Google Map
* Whois Name and Handle
* Whois Registration for IP address, Links and Entities

Server Cryptography:

* OpenSSL default negotiated CipherSuite
* Definitions, Values and Opinion on:
  * TLS Version
  * Key Exchange
  * Authentication
  * Encryption Cipher 
  * Cipher Mode
  * Message Authentication Code

Server Certificate (Supports RSA or EC certificates)

* Certificate visualisation
* Base64 certificate output
* All x509v3 certificate attributes
* Public Key RSA Modulus or EC Points and curve name
* Colorisation of the public key
* List of Subject Alternative Names

Handshake Details

* Connection Parameters
  * Server and Client Random from handshake
  * Server and Client TLS Random Date from handshake
  * Session master key
  * Session ID
  * Hex Output of Session Ticket
  * Session Ticket Lifetime 

Server Vulnerabilities

* Detection for common TLS misconfigurations or software vulnerabilities

Python libraries required:

* [Django](https://www.djangoproject.com/)
* [pyOpenSSL](https://github.com/pyca/pyopenssl)
* Modified version of [python Cryptography](https://github.com/pyca/cryptography) that provides some attributes from the <code>SSL Session struct/<code>
  * https://github.com/MiWCryptAnalytics/cryptography
* [pyasn1](http://pyasn1.sourceforge.net/)
* [python-geoip](https://github.com/mitsuhiko/python-geoip)
* [requests](https://github.com/kennethreitz/requests)


This code is released under BSD license 2015
