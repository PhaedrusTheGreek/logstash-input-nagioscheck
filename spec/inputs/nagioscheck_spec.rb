# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/nagioscheck"


describe LogStash::Inputs::Nagioscheck do

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "name" => "my_load_check", "command" => "/usr/local/sbin/check_load -w 1,2,3 -c 4,5,6",  "interval" => 100 } }
  end


  context "when we simulate certain output 1" do
    let(:input) { LogStash::Plugin.lookup("input", "nagioscheck").new("name" => "my_load_check", "command" => "echo 'Everything OK | load1=0.010;5.000;9.000;0; load5=0.060;5.000;9.000;0; load15=2.010;5.000;9.000;0;'", "interval" => 0) }
    let(:queue) { [] }

    before do
      input.register
      input.execute(queue)
    end

    after do
      input.stop
    end

    it "it parses out properly" do
      expect(queue.length).to eq 4

      expect(queue[0].get("value")).to eq 0.01

      expect(queue[1].get("value")).to eq 0.06
      expect(queue[1].get("label")).to eq "load5"     
      
      expect(queue[2].get("value")).to eq 2.01

      expect(queue[3].get("message")).to eq "Everything OK"
      expect(queue[3].get("status")).to eq "OK"
      expect(queue[3].get("took_ms")).to be > 0

    end

  end

  context "when we simulate certain output 2" do
    let(:input) { LogStash::Plugin.lookup("input", "nagioscheck").new("name" => "my_check", "command" => "echo 'Everything OK | users=4;20;50;0'", "interval" => 0) }
    let(:queue) { [] }

    before do
      input.register
      input.execute(queue)
    end

    after do
      input.stop
    end

    it "it parses out properly" do
      
      expect(queue.length).to eq 2

      expect(queue[0].get("value")).to eq 4
      expect(queue[0].get("warning")).to eq 20
      expect(queue[0].get("critical")).to eq 50     
      expect(queue[0].get("min")).to eq 0

      expect(queue[1].get("message")).to eq "Everything OK"
      expect(queue[1].get("status")).to eq "OK"
      expect(queue[1].get("took_ms")).to be > 0

    end

  end


  context "when we simulate certain output 3" do
    let(:input) { LogStash::Plugin.lookup("input", "nagioscheck").new("name" => "my_check", "command" => "echo 'Some Disk Data | /home/a-m=0;0;0 shared-folder:big=20 12345678901234567890=20'", "interval" => 0) }
    let(:queue) { [] }

    before do
      input.register
      input.execute(queue)
    end

    after do
      input.stop
    end

    it "it parses out properly" do
      
      expect(queue.length).to eq 4

      expect(queue[0].get("label")).to eq  "/home/a-m"     
      expect(queue[0].get("value")).to eq  0
      expect(queue[0].get("warning")).to eq  0 
      expect(queue[0].get("critical")).to eq  0
      expect(queue[1].get("label")).to eq  "shared-folder:big"     
      expect(queue[1].get("value")).to eq  20
      expect(queue[2].get("label")).to eq  "12345678901234567890"     
      expect(queue[2].get("value")).to eq  20

      expect(queue[3].get("status")).to eq  "OK"

    end

  end

  context "when we simulate certain output 4" do
    let(:input) { LogStash::Plugin.lookup("input", "nagioscheck").new("name" => "my_uom_check", "command" => "echo 'Some Float Parsing with Uom | time=0.002722s;0.000000;0.000000;0.000000;10.000000'", "interval" => 0) }
    let(:queue) { [] }

    before do
      input.register
      input.execute(queue)
    end

    after do
      input.stop
    end

    it "it parses out properly" do
      
      expect(queue.length).to eq 2

      expect(queue[0].get("label")).to eq  "time"     
      expect(queue[0].get("value")).to eq  0.002722
      expect(queue[0].get("uom")).to eq "s"
      expect(queue[0].get("max")).to eq 10
     
    end

  end

  context "when we simulate malformed output" do
    let(:input) { LogStash::Plugin.lookup("input", "nagioscheck").new("name" => "my_broken_plugin", "failure_tag" => "i_must_appear", "command" => "echo 'Some Status | invalid;perf data'", "interval" => 0) }
    let(:queue) { [] }

    before do
      input.register
      input.execute(queue)
    end

    after do
      input.stop
    end

    it "it tags with parse failure" do
      expect(queue[0].get("tags")).to include("i_must_appear")     
    end

  end
 
  context "when we have a string in the perf data" do
    let(:input) { LogStash::Plugin.lookup("input", "nagioscheck").new("name" => "my_broken_plugin", "failure_tag" => "i_must_appear", "command" => "echo 'String in perf data is parsed as 0| time=0.002722s;0.000000;string;0.000000;10.000000'", "interval" => 0) }
    let(:queue) { [] }

    before do
      input.register
      input.execute(queue)
    end

    after do
      input.stop
    end

    it "it parses it as 0" do
      expect(queue[0].get("critical")).to eq 0   
    end

  end


  context "when we have empty output" do
    let(:input) { LogStash::Plugin.lookup("input", "nagioscheck").new("name" => "my_broken_plugin", "failure_tag" => "i_must_appear", "command" => "echo ''", "interval" => 0) }
    let(:queue) { [] }

    before do
      input.register
      input.execute(queue)
    end

    after do
      input.stop
    end

    it "it's ignored" do
      expect(queue[0].get("status")).to eq "OK"   
    end

  end

  context "when a real check runs" do
    let(:input) { LogStash::Plugin.lookup("input", "nagioscheck").new("name" => "my_load_check", "command" => "/usr/local/sbin/check_load -w 0,2,3 -c 0,5,6", "interval" => 0) }
    let(:queue) { [] }

    before do
      input.register
      input.execute(queue)
    end

    after do
      input.stop
    end

    it "it parses out properly" do

      expect(queue[0].get('type')).to eq "nagiosmetric"
      expect(queue[0].get('name')).to eq "my_load_check"
      expect(queue[0].get('label')).to eq "load1"
      expect(queue[0].get('warning')).to eq 0
      expect(queue[0].get('critical')).to eq 0
      expect(queue[0].get('min')).to eq 0

      expect(queue[1].get('label')).to eq "load5"
      expect(queue[1].get('warning')).to eq 2
      expect(queue[1].get('critical')).to eq 5
      expect(queue[1].get('min')).to eq 0

      expect(queue[2].get('label')).to eq "load15"
      expect(queue[2].get('warning')).to eq 3
      expect(queue[2].get('critical')).to eq 6
      expect(queue[2].get('min')).to eq 0

      expect(queue[3].get('message')).not_to be_nil
      expect(queue[3].get('message')).to include("load average")
      expect(queue[3].get('status')).to eq "CRITICAL"
      expect(queue[3].get('name')).to eq "my_load_check"
      expect(queue[3].get('took_ms')).to be > 0
      expect(queue[3].get('type')).to eq "nagioscheck"

    end


  end

end
