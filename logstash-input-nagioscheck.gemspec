Gem::Specification.new do |s|
  s.name          = 'logstash-input-nagioscheck'
  s.version       = '0.1.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Logstash NagiosCheck Filter'
  s.description   = 'Parses the output of Nagios Checks (via exec input)'
  s.homepage      = 'http://www.elastic.co'
  s.authors       = ['Jay Greenberg']
  s.email         = 'jay.greenberg@elastic.co'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'logstash-input-exec', ">= 3.3.0"
  s.add_runtime_dependency 'stud', '>= 0.0.22'
  s.add_development_dependency 'logstash-devutils', '>= 0.0.16'
  s.add_development_dependency 'logstash-input-exec', ">= 3.3.0"
end
