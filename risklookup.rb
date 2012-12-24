#!/usr/bin/ruby

require 'rubygems'
require 'resolv'
require 'ipaddress'
require 'getopt/std'
require 'pp'
require 'orderedhash'
require 'ruby-debug'

HTTP_BL = "dnsbl.httpbl.org"
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

#options
# -o xml|csv
#    open file, write, close
# -f filename
# -h help
#    usage display
# -i input file
# -A API key for Project Honeypot

def setAPI(opt)
  if opt["A"]
    api_key = opt["A"]
  else
    api_key = "obkvwevadnqw"
  end
  return api_key
end


def usage
  puts "usage: ./risklookup.rb -A [apikey] -o [xml|csv] -f [output file] -i [input file] -h [ipaddress|network/mask]"
  puts "examples: ./risklookup 10.2.3.4"
  puts " 	  ./risklookup 205.22.3.0/24"
end

def input_file(filename)
  ip = Array.new
  linecount = 0
  puts "Opening filename: #{filename}"
  File.open(filename,"r") do |infile|
    while (line = infile.gets)
      begin
        ip.push(line)
        linecount = linecount + 1
      rescue
        puts "Parse error on line #{linecount} in #{filename}."
        exit
      end
    end
  end
  return ip
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
   risk_type.each { |type,mask|
    # puts "#{score & mask} :: #{score} #{mask}"
     if ((mask != 0) and (score & mask) == mask)
      risk_descr = risk_descr + type + " "
     end
    }
  return risk_descr
end


def lookup(ip,api_key)
  results = Array.new
  count = 0
  ip.each do |addr|
    query = "#{api_key}.#{addr.reverse.to_s.split(".in-addr.arpa").first}.#{HTTP_BL}"
    # obkvwevadnqw.2.1.9.127.dnsbl.httpbl.org
      begin
        puts query
        res = Resolv.getaddress(query)
        risk_score = IPAddress res
        result = {"ip" => addr,
                  "value" => res,
                  "days_last" => risk_score[1],
                  "threat_level" => risk_score[2],
                  "type" => risk_score[3],
                  "threat_type" => convert_risk_type(Integer(risk_score[3]))
        }
        results = (results << result).flatten
      rescue
        res = "No risk score for this IP or invalid api key"
      ensure
        count = count + 1
      end

    #puts "IP :: #{addr} ====> Risk: res"
    puts "IP :: #{result["ip"]} ====> Risk: #{res} :::: Score: #{result["days_last"]} :: #{result["threat_level"]} :: #{result["threat_type"]} (#{result["type"]})" unless res.eql? "No risk score for this IP or invalid api key"
    #output into xml
    #output into csv
    puts "#{count} records queried"
  end
  return results
end

def output(results,opt)
  if (opt["o"] == "xml")
      xml = "<riskreading>"
      results.each do |result|
        xml = xml + "<ipaddress ip=\"#{result["ip"]}\" value=\"#{result["value"]}\">" 
    end
    xml = xml + "</riskreading>"
    pp xml
  end
#puts "  <ipaddress ip=\"#{addr}\" risk=\"#{res}\"/>" 
  if opt["o"] == "csv"
    results.each do |result|
    end
  end
#puts "#{addr},#{days_last},#{threat_level},#{type}"
end

def main()

  opt = Getopt::Std.getopts("o:sf:A:")
  total_searched = 0
  xml = "<risklist>"
  results = Array.new
  api_key = setAPI(opt)
  ip = nil

  if opt["f"]
    filename=opt["f"]
    list = input_file(filename)
  elsif
    if ARGV.last == nil
      usage
      exit
    elsif
      list = ARGV.last
    end
  end

  list.each do |ip|
    ipaddr = IPAddress ip
    results = (results << lookup(ipaddr,api_key)).flatten
  end
  output(results,opt)
  puts "#{results.count} records with valid results"
end
# close xml

# close csv
#  puts "Completed lookup -> #{total_searched} records queried" unless !opt["s"]

main()
exit
