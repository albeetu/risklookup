#!/usr/bin/ruby

require 'rubygems'
require 'resolv'
require 'ipaddr'
require 'ipaddress'
# obkvwevadnqw.2.1.9.127.dnsbl.httpbl.org
# usage: ./risklookup -o xml|csv [ipaddress] 

API_KEY = "obkvwevadnqw"
HTTP_BL = "dnsbl.httpbl.org"

def usage
  puts "usage: ./risklookup.rb -o xml|csv [ipaddress{/range}]"
  puts "examples: ./risklookup 10.2.3.4"
  puts " 	  ./risklookup 205.22.3.0/24"
end

if ARGV[0] == nil
  usage
exit
end

begin
  ip = IPAddress ARGV[0]
rescue
  puts "#{ARGV[0]} is an invalid address"
  ip = nil
  exit
end

ip.each do |addr|
  query = "#{API_KEY}.#{addr.reverse.to_s.split(".in-addr.arpa").first}.#{HTTP_BL}"
  # obkvwevadnqw.2.1.9.127.dnsbl.httpbl.org
  begin
    res = Resolv.getaddress(query)
  rescue
    res = "No record found"
  end
  puts "#{query} ====> #{res}"
end
