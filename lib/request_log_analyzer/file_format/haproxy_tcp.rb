module RequestLogAnalyzer::FileFormat

  class Haproxy2 < RequestLogAnalyzer::FileFormat::Base

    extend CommonRegularExpressions

    # substitute version specific parts of the haproxy entry regexp.
    def self.compose_regexp(millisecs, backends, counters, connections, queues)
      %r{
        \S+\s\s?\d+\s\d+:\d+:\d+\s
        (#{ip_address})\s # syslog_ip
        (\S+)\[(\d+)\]:\s # process_name '[' process_pid ']:'
        (#{ip_address}):\d+\s # client_ip ':' client_port
        \[(#{timestamp('%d/%b/%Y:%H:%M:%S')})#{millisecs}\]\s # '[' accept_date ']'
        (\S+)\s # frontend_name
        #{backends}
        (\d+|-1)\/(\d+|-1)\/(\d+|-1)\s # queue_time '/' connect_time '/' total_time
        \+?(\d+)\s # bytes_read
        (\w|-)(\w|-)\s # termination_state
        #{connections}
        #{queues}
      }x
    end

    # Define line types
    # Oct 14 04:32:46 127.0.0.1 haproxy[2009]: 76.14.102.24:51662 [14/Oct/2010:04:32:46.413] Proxy_EU_STATUS_PAGE_ONLY_80 Proxy_EU_STATUS_PAGE_ONLY_80/<NOSRV> -1/-1/4 9331 PR 0/0/0/0/0 0/0
    # line definition for haproxy 1.3 and higher
    line_definition :haproxy13 do |line|
      line.header = true
      line.footer = true
      #line.teaser = /\.\d{3}\] \S+ \S+\/\S+ / # .millisecs] frontend_name backend_name/server_name

      line.regexp = compose_regexp(
        '\.\d{3}', # millisecs
        '(\S+)\/(\S+)\s', # backend_name '/' server_name
        '(\d+|-1)\/(\d+|-1)\/(\d+|-1)\/(\d+|-1)\/\+?(\d+)\s', # Tq '/' Tw '/' Tc '/' Tr '/' Tt
        '(\d+)\/(\d+)\/(\d+)\/(\d+)\/\+?(\d+)\s', # actconn '/' feconn '/' beconn '/' srv_conn '/' retries
        '(\d+)\/(\d+)\s' # srv_queue '/' backend_queue
      )

      #line.capture(:syslog_timestamp).as(:string)
      line.capture(:syslog_ip).as(:string)
      line.capture(:process_name).as(:string)
      line.capture(:process_pid).as(:integer)
      line.capture(:client_ip).as(:string)
      line.capture(:timestamp).as(:timestamp)
      line.capture(:frontend_name).as(:string)
      line.capture(:backend_name).as(:string)
      line.capture(:server_name).as(:string)
      line.capture(:queue_time).as(:nillable_duration, :unit => :msec)
      line.capture(:connect_time).as(:nillable_duration, :unit => :msec)
      line.capture(:total_time).as(:duration, :unit => :msec)
      line.capture(:bytes_read).as(:traffic, :unit => :byte)
      line.capture(:termination_event_code).as(:nillable_string)
      line.capture(:terminated_session_state).as(:nillable_string)
      line.capture(:actconn).as(:integer)
      line.capture(:feconn).as(:integer)
      line.capture(:beconn).as(:integer)
      line.capture(:srv_conn).as(:integer)
      line.capture(:retries).as(:integer)
      line.capture(:srv_queue).as(:integer)
      line.capture(:backend_queue).as(:integer)
    end


    # Define the summary report
    report do |analyze|
      analyze.hourly_spread :field => :timestamp

      analyze.frequency :client_ip,
        :title => "Hits per IP"

      analyze.frequency :frontend_name,
        :title => "Hits per frontend service"

      analyze.frequency :backend_name,
        :title => "Hits per backend service"

      analyze.frequency :server_name,
        :title => "Hits per backend server"

      analyze.frequency :status_code,
        :title => "HTTP response code frequency"

      analyze.traffic :bytes_read,
        :title => "Traffic per frontend service",
        :category => lambda { |r| "#{r[:frontend_name]}"}

      analyze.traffic :bytes_read,
        :title => "Traffic per backend service",
        :category => lambda { |r| "#{r[:backend_name]}"}

      analyze.traffic :bytes_read,
        :title => "Traffic per backend server",
        :category => lambda { |r| "#{r[:server_name]}"}

      analyze.duration :connect_time,
        :title => "Time waiting for backend response",
        :category => lambda { |r| "#{r[:backend_name]}"}

      analyze.duration :total_time,
        :title => "Total time spent on request",
        :category => lambda { |r| "#{r[:backend_name]}"}
    end

    # Define a custom Request class for the HAProxy file format to speed up
    # timestamp handling. Shamelessly copied from apache.rb
    class Request < RequestLogAnalyzer::Request

      MONTHS = {'Jan' => '01', 'Feb' => '02', 'Mar' => '03', 'Apr' => '04', 'May' => '05', 'Jun' => '06',
                'Jul' => '07', 'Aug' => '08', 'Sep' => '09', 'Oct' => '10', 'Nov' => '11', 'Dec' => '12' }

      # Do not use DateTime.parse, but parse the timestamp ourselves to return
      # a integer to speed up parsing.
      def convert_timestamp(value, definition)
        "#{value[7,4]}#{MONTHS[value[3,3]]}#{value[0,2]}#{value[12,2]}#{value[15,2]}#{value[18,2]}".to_i
      end

      # Make sure that the strings '-' or '{}' or '' are parsed as a nil value.
      def convert_nillable_string(value, definition)
        value =~ /-|\{\}|^$/ ? nil : value
      end

      # Make sure that -1 is parsed as a nil value.
      def convert_nillable_duration(value, definition)
        value == '-1' ? nil : convert_duration(value, definition)
      end

    end
  end
end
