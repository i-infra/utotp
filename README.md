MinTOTP
=======

uTOTP is a minimal TOTP generator written in Python, targetting MicroPython.

--------

* [License](#license)
* [Thanks](#thanks)


Introduction
------------

TOTP stands for Time-Based One-Time Password. Many websites and services
require two-factor authentication (2FA) or multi-factor authentication
(MFA) where the user is required to present two or more pieces of
evidence:

  - Something only the user knows, e.g., password, passphrase, etc.
  - Something only the user has, e.g., hardware token, mobile phone, etc.
  - Something only the user is, e.g., biometrics.

A TOTP value serves as the second factor, i.e., it proves that the user
is in possession of a device (e.g., mobile phone) that contains a TOTP
secret key from which the TOTP value is generated. Usually the service
provider that provides a user's account also issues a secret key encoded
either as a Base32 string or as a QR code. This secret key is added to
an authenticator app (e.g., Google Authenticator) on a mobile device.
The app can then generate TOTP values based on the current time.
By default, it generates a new TOTP value every 30 seconds.

MinTOTP is a Python tool that can be used to generate TOTP values from a
secret key. Additionally, it exposes its functionality as module-level
functions for Python developers. It can be used on any system with
Python 3.4 or later installed on it.


Source Code
-----------

At the heart of the TOTP algorithm lies the HOTP algorithm. HOTP stands
for HMAC-based One-Time Password. HMAC stands for Hash-based Message
Authentication Code. Here are the relevant RFCs to learn more about
these algorithms:

  - [RFC 2104]: HMAC: Keyed-Hashing for Message Authentication
  - [RFC 4226]: HOTP: An HMAC-Based One-Time Password Algorithm
  - [RFC 6238]: TOTP: Time-Based One-Time Password Algorithm

[RFC 2104]: https://tools.ietf.org/html/rfc2104
[RFC 4226]: https://tools.ietf.org/html/rfc4226
[RFC 6238]: https://tools.ietf.org/html/rfc6238

The source code in [`utotp.py`][src] generates TOTP values from a
secret key and current time. 

The `totp()` function implements the TOTP algorithm. It is a thin
wrapper around the HOTP algorithm. The TOTP value is obtained by
invoking the HOTP function with the secret key and the number of time
intervals (30 second intervals by default) that have elapsed since Unix
epoch (1970-01-01 00:00:00 UTC).

[RFC 2104-5]: https://tools.ietf.org/html/rfc4226#section-5


Install
-------

MinTOTP requires micropython. 


Get Started
-----------

This section presents a few examples to quickly get started with
uTOTP.

Note that this section uses a few example secret keys and QR codes. They
are merely examples that come with this project for you to quickly test
the program with. They should not be used for any real account that
requires TOTP-based two-factor authentication. Usually, the issuer of a
real account (such as an account on a website or an organization) would
also issue a secret key or a secret QR code to you which you must use to
generate TOTP values for the purpose of logging into that account.


### With Base32 Key

License
-------

This is free and open source software. You can use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of it,
under the terms of the MIT License. See [LICENSE.md][L] for details.

This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND,
express or implied. See [LICENSE.md][L] for details.

[L]: LICENSE.md


Support
-------

To report bugs, suggest improvements, or ask questions, please create a
new issue at <http://github.com/i-infra/utotp/issues>.


Thanks
------

Thanks to [Susam Pal][https://github.com/susam] and [Prateek Nischal][PN] for all the great work!
[prateeknischal/qry/util/totp.py][PNTOTP] [susam/mintotp/blob/master/mintotp.py][https://github.com/susam/mintotp/blob/master/mintotp.py]

[PN]: https://github.com/prateeknischal
[PNTOTP]: https://github.com/prateeknischal/qry/blob/master/util/totp.py
