#!/usr/bin/ruby

require 'rubygems'
require 'resolv'
require 'ipaddress'
require 'getopt/std'
require 'pp'
require 'orderedhash'
require 'ruby-debug'

# obkvwevadnqw.2.1.9.127.dnsbl.httpbl.org
# usage: ./risklookup -o xml|csv [ipaddress] 

# <risklist>
#    <ipaddress ip="123.3.3.3" value=""/>
#    <ipaddress ip="125.5.5.2" value="127.2.45.2"/>
# </risklist>

# 123.3.3.3,123.2.2.2
# 123.3.3.4,nil


# Result
# Example: 127.3.5.1
# 1st octet - ignore
# 2nd octet - Days last time activty was recorded
# 3rd octet - threat score
# 4th octet - type of threat

#Threat types

API_KEY = "obkvwevadnqw"
HTTP_BL = "dnsbl.httpbl.org"
opt = Getopt::Std.getopts("o:s")
total_searched = 0
xml = "<risklist>"

#options
# -o xml|csv
#    open file, write, close
# -f filename
# -h help
#    usage display
# -i input file

def usage
  puts "usage: ./risklookup.rb -o [xml|csv] -f [output file] -i [input file] -h [ipaddress|network/mask]"
  puts "examples: ./risklookup 10.2.3.4"
  puts " 	  ./risklookup 205.22.3.0/24"
end

def input_file(filename)
  linecount = 0
  File.open(filename,"r") do |infile|
    while (line = infile.gets)
      begin
        ip = IPAddress line
        linecount = linecount + 1
      rescue
        puts "Parse error on line #{linecount} in #{filename}."
        file.close
        exit
      end
  file.close
  return address_list
end


def convert_risk_type(score)
  risk_type = OrderedHash.new
  risk_descr = String.new
  risk_type["Engine"] = 0
  risk_type["Suspicious"] = 1
  risk_type["Harvester"] = 2
  risk_type["Comment Spammer"] = 4
   if (score == 0) 
      return "Engine"
   end            
   #pp risk_type 
   risk_type.each { |type,mask|
    # puts "#{score & mask} :: #{score} #{mask}"
     if ((mask != 0) and (score & mask) == mask)
      risk_descr = risk_descr + type + " "
     end
    }
  return risk_descr
end

if opt["f"]
  
  ip = input_file(

#if -f flag is on
# ip = input_file(filename)
#else
if ARGV.last == nil
  usage
exit
end

begin
  ip = IPAddress ARGV.last
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
    risk_score = IPAddress res
    days_last = risk_score[1]
    threat_level = risk_score[2]
    type = Integer(risk_score[3])
    threat_type = convert_risk_type(type)
  rescue
    res = "No risk score for this IP"
  ensure
    # May not need anything here
  end
  # puts "IP :: #{addr} ====> Risk: res"
  puts "IP :: #{addr} ====> Risk: #{res} :::: Score: #{days_last} :: #{threat_level} :: #{threat_type} (#{type})" if !res.eql? "No risk score for this IP"
  total_searched = total_searched + 1
  #output into xml
  puts "  <ipaddress ip=\"#{addr}\" risk=\"#{res}\"/>" 
  #output into csv
end

# close xml
# close csv
puts "Completed lookup -> #{total_searched} records queried" if !opt["s"]
exit(0)
