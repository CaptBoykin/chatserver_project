# chatserver_project
A small chat server project I'm still working on to improve my C

## Current features
* SSL(TLS) connections
* IP whitelisting / blacklisting
* Username / password accounting with password hashing

## Notes
* All configurations are made in /configs/server.cfg
* Will require modifying main.c as this is still testing

## Install
* make (non debugging, output to STDOUT dependant upon `VERBOSE=` in `/configs/server.cfg`)
* make debug (extra output to STDOUT on the server side from `d_print()`)
* make clean (wipe the slate)

## Running
* ./chatserver (or ./chatserver_debug)  <config file>

** Best results work on `nc` or `telnet` client for linux.  Windows has some functionality but the ANSI escape sequences won't work as intended. ** 

# TO DO:
* Fix: Server exits unexpectedly on empty (newline)
* Fix: ANSI codes for windows
* Fix: Server exits on host disconnect
* migrate all changes from past 72hrs to ssl_serv.c
* launch options aside from config file (main.c)
* DB file encryption
* pretty up formatting
* Alternate commands to allow misc features (file transfer, etc)
