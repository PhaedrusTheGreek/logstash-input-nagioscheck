require "logstash/inputs/nagioscheck"

LogStash::PLUGIN_REGISTRY.add(:modules, "nagios", LogStash::Modules::Scaffold.new("nagios", File.join(File.dirname(__FILE__), "..", "module")))
LogStash::PLUGIN_REGISTRY.add(:input, "nagios", LogStash::Inputs::Nagioscheck)
