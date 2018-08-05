# sslfollow

Extracts AES etc. keys from TLS connections, via ld_preload.  This only works for browsers which make use of 
NSS.  It used to work with chromium, but it seems they have now switched to BoringSSL.  It still works with Firefox.

I have bundled some headers which are missing from the libnss3-dev package, to save having to grab them

Just do

```
sudo apt-get install libnss3-dev 
make

LD_PRELOAD="./follow.so" firefox

```
