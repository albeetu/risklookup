risklookup
==========

Project Honeypot allows you to track report spammers and other repetious malicious activity from botnets. Various modules are provided so that you can provide a continuous stream of data back to the network.

The risklookup script interfaces with a DNS server PHP (project honeypot) provides to get known risk readings.

Usage

usage:    ./risklookup.rb -o xml|csv [ipaddress{/range}]
examples: ./risklookup 10.2.3.4
          ./risklookup 205.22.3.0/24
          


