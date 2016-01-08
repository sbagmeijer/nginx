nginx-mbedtls
========

[nginx](http://www.nginx.org) with support for [mbed TLS](https://tls.mbed.org/).

Overview
--------

This is a fork of the nginx development branch that allows the user to use mbed TLS instead of OpenSSL.  This may be useful for those seeking to further minimise the memory footprint of the webserver, or for those that happen to dislike OpenSSL for some reason.

Also the nginx-mbedtls is a clone from [Yawning nginx-polarss] (https://github.com/Yawning/nginx-polarssl), I only changed everything to mbedtls.

Motivation
--------

mbed TLS seemed like an amazing library and the author felt that a simple project to get used to the APIs was the best way to learn it's internals.  Additionally there are not many webservers that use SSL libraries other than OpenSSL ([Hiawatha](http://www.hiawatha-webserver.org/) is a notable exception), and there should be more.

Installation
--------

See [nginx's installation options](http://wiki.nginx.org/InstallOptions) for how to configure/install nginx.

This fork adds:

    --with-mbedtls - Attempt to use the system mbed TLS installation.
    --with-mbedtls=path - Compile nginx statically with the mbed TLS source code located at "path".

For example:

    ./configure --with-http_ssl_module --with-mbedtls=~/Packages/mbedtls-2
    gmake
    gmake install

Note that due to the Makefiles shipped by mbed TLS using GNU make style conditionals, GNU make must be used if --with-mbedtls=path is used.

Configuration
--------

With a few exceptions configuration is identical to the standard SSL support.

 - ssl_protocols does not support "SSLv2".
 - ssl_engine is not a valid config option when using mbed TLS.
 - ssl_prefer_server_ciphers has no effect.
 - ssl_session_cache builtin is not supported.
 - ssl_ciphers_list expects a ':' separated list of cipher suites.
 - ssl_stapling and related options are not supported.

Supported Ciphersuites
--------

 - TLS-RSA-WITH-RC4-128-MD5
 - TLS-RSA-WITH-RC4-128-SHA
 - TLS-RSA-WITH-3DES-EDE-CBC-SHA
 - TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA
 - TLS-RSA-WITH-AES-128-CBC-SHA
 - TLS-DHE-RSA-WITH-AES-128-CBC-SHA
 - TLS-RSA-WITH-AES-256-CBC-SHA
 - TLS-DHE-RSA-WITH-AES-256-CBC-SHA
 - TLS-RSA-WITH-AES-128-CBC-SHA256
 - TLS-RSA-WITH-AES-256-CBC-SHA256
 - TLS-DHE-RSA-WITH-AES-128-CBC-SHA256
 - TLS-DHE-RSA-WITH-AES-256-CBC-SHA256
 - TLS-RSA-WITH-CAMELLIA-128-CBC-SHA
 - TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA
 - TLS-RSA-WITH-CAMELLIA-256-CBC-SHA
 - TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA
 - TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256
 - TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256
 - TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256
 - TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256
 - TLS-RSA-WITH-AES-128-GCM-SHA256
 - TLS-RSA-WITH-AES-256-GCM-SHA384
 - TLS-DHE-RSA-WITH-AES-128-GCM-SHA256
 - TLS-DHE-RSA-WITH-AES-256-GCM-SHA384

Note: This depends on what ciphers were compiled into mbed TLS at build time.  Additionally certain extremely weak ciphersuites are explicitly not supported by nginx-mbedtls.

Know Issues/Implementation Differences
--------

nginx-polarssl Issues:

 - See the [github issue tracker](https://github.com/Yawning/nginx-polarssl/issues?sort=created&state=open)

PolarSSL Issues:

 - PolarSSL 1.2.5 has a memory leak. (Fix: https://github.com/polarssl/polarssl/commit/c0463502ff89db15c9bcfee33878678b7fd14cef)
 - Support for SSL v2.0 ClientHello was removed from PolarSSL 1.2.x.  Some applications rely on this to be supported or will not handshake correctly.  This is scheduled to be fixed in a future version of PolarSSL.

Implementation differences:

 - SSLv2.0 is not supported, and will not be supported.
 - OCSP stapling is not and more than likely will not be supported.
 - ECDH is not yet supported by mbed TLS.

License
--------

The changes added by nginx-mbedtls are distrubuted under the [nginx license](http://nginx.org/LICENSE) (Also see https://tls.mbed.org/foss-license-exception).
