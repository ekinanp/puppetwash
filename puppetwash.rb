#!/usr/bin/env ruby

require 'wash'
require 'puppetdb'
require 'json'
require 'yaml'


def make_readable(value)
  if value.kind_of? String
    value
  else
    JSON.pretty_generate(value)
  end
end

# Entry is a wrapper to Wash::Entry that persists
# the config so that the client can be recreated
#
# TODO: Store the instance-specific config instead.
# If this becomes a common-enough pattern, maybe
# have some way for core Wash to store this info?
class Entry < Wash::Entry
  state :config

  def client(pe_name)
    conf = @config[pe_name]
    if conf['rbac_token']
      # PE token-based auth
      PuppetDB::Client.new({
        server: conf['puppetdb_url'],
        token:  conf['rbac_token'],
        cacert: conf['cacert']
      })
    else
      # Cert-based auth
      PuppetDB::Client.new({
        server: conf['puppetdb_url'],
        pem: {
          'ca_file' => conf['cacert'],
          'key'     => conf['key'],
          'cert'    => conf['cert']
        }
      })
    end
  end
end

class Puppetwash < Entry
  label 'puppet'
  is_singleton
  parent_of 'PEInstance'

  def init(config)
    @config = config
  end

  def list
    @config.keys.map do |name|
       PEInstance.new(name)
    end
  end
end

class PEInstance < Entry
  label 'pe_instance'
  parent_of 'NodesDir'

  def initialize(name)
    @name = name
  end

  def list
    [NodesDir.new('nodes', name)]
  end
end

class NodesDir < Entry
  label 'nodes_dir'
  is_singleton
  parent_of 'Node'
  state :pe_name

  def initialize(name, pe_name)
    @name = name
    @pe_name = pe_name
  end

  def list
    response = client(@pe_name).request('nodes', nil)
    response.data.map do |node|
      Node.new(node, @pe_name)
    end
  end
end

class Node < Entry
  label 'node'
  parent_of 'Catalog', 'FactsDir', 'ReportsDir'
  state :pe_name

  def initialize(node, pe_name)
    @name = node['certname']
    @pe_name = pe_name
    @partial_metadata = node
    prefetch :list
  end

  def list
    [
      Catalog.new('catalog.json', @name, @pe_name),
      FactsDir.new('facts', @name, @pe_name),
      ReportsDir.new('reports', @name, @pe_name)
    ]
  end
end

class Catalog < Entry
  label 'catalog'
  is_singleton
  state :node_name, :pe_name

  def initialize(name, node_name, pe_name)
    @name = name
    @node_name = node_name
    @pe_name = pe_name
  end

  def read
    response = client(@pe_name).request("catalogs/#{@node_name}", nil)
    make_readable(response.data)
  end
end

class FactsDir < Entry
  label 'facts_dir'
  is_singleton
  parent_of 'Fact'
  state :node_name, :pe_name

  def initialize(name, node_name, pe_name)
    @name = name
    @node_name = node_name
    @pe_name = pe_name
  end

  def list
    response = client(@pe_name).request(
      'facts',
      [:'=', :certname, @node_name]
    )
    response.data.map do |fact|
      Fact.new(fact['name'], fact['value'], @node_name, @pe_name)
    end
  end
end

class Fact < Entry
  label 'fact'
  state :node_name, :pe_name

  def initialize(name, value, node_name, pe_name)
    @name = name
    @value = value
    @node_name = node_name
    @pe_name = pe_name
    prefetch :read
  end

  def read
    make_readable(@value)
  end
end

# Report relies on end_time and hash. The others are included as useful metadata.
METADATA_FIELDS = {
  'end_time': 'string',
  'environment': 'string',
  'status': 'string',
  'noop': 'boolean',
  'puppet_version': 'string',
  'producer': 'string',
  'hash': 'string'
}

class ReportsDir < Entry
  label 'reports_dir'
  is_singleton
  parent_of 'Report'
  state :node_name, :pe_name

  def initialize(name, node_name, pe_name)
    @name = name
    @node_name = node_name
    @pe_name = pe_name
  end

  def list
    response = client(@pe_name).request(
      'reports',
      [:extract,
        METADATA_FIELDS.keys,
        [:'=', :certname, @node_name]]
    )
    response.data.map do |report|
      Report.new(report, @node_name, @pe_name)
    end
  end
end

class Report < Entry
  label 'report'
  attributes :mtime
  partial_metadata_schema(
      type: 'object',
      properties: METADATA_FIELDS.map { |k, v| [k, { type: v }] }.to_h
  )
  state :node_name, :pe_name, :hash

  def initialize(report, node_name, pe_name)
    @name = report['end_time']
    @node_name = node_name
    @pe_name = pe_name
    @hash = report['hash']
    @partial_metadata = report
    @mtime = Time.parse(report['end_time'])
  end

  def read
    response = client(@pe_name).request(
      'reports',
      [:and, [:'=', :certname, @node_name], [:'=', :hash, @hash]]
    )
    make_readable(response.data)
  end
end

Wash.enable_entry_schemas
Wash.prefetch_entry_schemas
Wash.pretty_print
Wash.run(Puppetwash, ARGV)
