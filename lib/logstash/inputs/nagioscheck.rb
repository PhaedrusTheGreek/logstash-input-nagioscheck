# encoding: utf-8
require "logstash/inputs/exec"
require "logstash/namespace"
require "stud/interval"
require "socket" # for Socket.gethostname
require 'securerandom'

# Generate a repeating message.
#
# This plugin is intented only as an example.

class LogStash::Inputs::Nagioscheck < LogStash::Inputs::Exec
  config_name "nagioscheck"

  # Name of the check
  config :name, :validate => :string, :required => true

  # Custom parse failure tag
  config :failure_tag, :validate => :string, :default => "_nagioscheckparsefailure"
  
  # Override the execute routine from the exec input
  def execute(queue)
    start = Time.now
    output = exit_status = nil
    begin
      @logger.debug? && @logger.debug("Running exec", :command => @command)
      output, exit_status = run_command()
    rescue StandardError => e
      @logger.error("Error while running command",
        :command => @command, :e => e, :backtrace => e.backtrace)
    rescue Exception => e
      @logger.error("Exception while running command",
        :command => @command, :e => e, :backtrace => e.backtrace)
    end
    duration = Time.now - start
    unless exit_status.nil? #exit status will be nil if the command never completed running
      @logger.debug? && @logger.debug("Command completed", :command => @command, :duration => duration)
      @codec.decode(output) do |event|
        decorate(event)

        cmd_message, cmd_perf = event.get("message").split('|')

        event.set("check_uuid", SecureRandom.uuid)

        unless cmd_perf.nil?
          cmd_perf.strip.split_by_spaces_except_single_quoted.each { |metric| 
    
              results = parse_performance(metric)
    
              if results.nil?
                
                @logger.warn("Error parsing nagios performance data (malformed)", :raw => event.get("message"))
                event.tag(@failure_tag)
    
              else 
    
                perf_event = event.clone
                perf_event.remove("message")

                perf_event.set("type", "nagiosmetric")
                perf_event.set("name", @name)
                perf_event.set("label", results[1])
                perf_event.set("uom", results[3])
                perf_event.set("value", results[2].to_f)
                perf_event.set("warning", results[4].to_f)
                perf_event.set("critical", results[5].to_f)
                perf_event.set("min", results[6].to_f)
                perf_event.set("max", results[7].to_f)
                
                queue << perf_event
    
              end
    
          }
        end

        event.set("host", @hostname)
        event.set("command", @command)
        event.set("type", "nagioscheck")
        event.set("message", cmd_message.nil? ? "" : cmd_message.strip)
        event.set("name", @name)
        event.set("took_ms", duration * 1000)
        event.set("status_code", exit_status)
        event.set("status", nice_status(exit_status))
        
        queue << event

      end
    end
    duration
  end
 
end # class LogStash::Inputs::Nagioscheck

class String
  def split_by_spaces_except_single_quoted
  self.split(/\s(?=(?:[^']|'[^']*')*$)/)
  end
end

def nice_status(status) 
	case status
  when 0
		return "OK"
	when 1
		return "WARNING"
	when 2
		return "CRITICAL"
	when 3
		return "UNKNOWN"
  else 
    return "INVALID STATUS"
  end
end


def parse_performance(perf)
  
  # As per https://github.com/nagios-plugins/nagios-plugin-perl/blob/master/lib/Nagios/Monitoring/Plugin/Performance.pm

  value = /[-+]?[\d\.,]+/
  value_re = /#{value}(?:e#{value})?/
  value_with_negative_infinity = /#{value_re}|~/
  
  regex = /^'?([^'=]+)'?=(#{value_re})([\w%]*);?(#{value_with_negative_infinity}\:?#{value_re}?)?;?(#{value_with_negative_infinity}\:?#{value_re}?)?;?(#{value_re})?;?(#{value_re})?/o
  regex.match(perf)

end