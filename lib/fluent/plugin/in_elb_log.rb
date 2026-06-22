require 'time'
require 'zlib'
require 'fileutils'
require 'cgi'
require 'aws-sdk-s3'
require 'aws-sdk-ec2'
require 'aws-sdk-sqs'
require 'aws-sdk-sts'
require 'fluent/input'
require 'digest/sha1'

class Fluent::Plugin::Elb_LogInput < Fluent::Plugin::Input
  Fluent::Plugin.register_input('elb_log', self)

  helpers :timer

  SQS_NOTIFICATION_ID = 'fluent-plugin-elb-log'

  LOGFILE_REGEXP = /^((?<prefix>.+?)\/|)AWSLogs\/(?<account_id>[0-9]{12})\/elasticloadbalancing\/(?<region>.+?)\/(?<logfile_date>[0-9]{4}\/[0-9]{2}\/[0-9]{2})\/[0-9]{12}_elasticloadbalancing_.+?_(?<logfile_elb_name>[^_]+)_(?<logfile_timestamp>[0-9]{8}T[0-9]{4}Z)_(?<elb_ip_address>.+?)_(?<logfile_hash>.+)\.log(.gz)?$/
  ACCESSLOG_REGEXP = /^((?<type>[a-z0-9]+) )?(?<time>\d{4}-\d{2}-\d{2}T\d{2}\:\d{2}\:\d{2}\.\d{6}Z) (?<elb>\S+) (?<client>\S+)\:(?<client_port>\S+) (?<target>[^:\s]+)(?::(?<target_port>\S+))? (?<request_processing_time>\S+) (?<target_processing_time>\S+) (?<response_processing_time>\S+) (?<elb_status_code>\S+) (?<target_status_code>\S+) (?<received_bytes>\S+) (?<sent_bytes>\S+) \"(?<request_method>\S+) (?<request_uri>.*) (?<request_protocol>HTTP\/[0-9.]+|-)\" \"(?<user_agent>.*?)\" (?<ssl_cipher>\S+) (?<ssl_protocol>\S+) (?<target_group_arn>\S+) \"(?<trace_id>\S+)\" \"(?<domain_name>\S+)\" \"(?<chosen_cert_arn>\S+)\" (?<matched_rule_priority>\S+) (?<request_creation_time>\S+) \"(?<actions_executed>\S+)\" \"(?<redirect_url>\S+)\" \"(?<error_reason>\S+)\" \"(?<target_port_list>\S+)\" \"(?<target_status_code_list>\S+)\" \"(?<classification>\S+)\" \"(?<classification_reason>\S+)\" (?<conn_trace_id>\S+)/
  config_param :access_key_id, :string, default: nil, secret: true
  config_param :secret_access_key, :string, default: nil, secret: true
  config_param :region, :string
  config_param :s3_bucketname, :string, default: nil
  config_param :s3_prefix, :string, default: nil
  config_param :tag, :string, default: 'elb.access'
  config_param :timestamp_file, :string, default: nil
  config_param :refresh_interval, :integer, default: 300
  config_param :buf_file, :string, default: './fluentd_elb_log_buf_file'
  config_param :http_proxy, :string, default: nil
  config_param :start_time, :string, default: nil
  config_param :delete, :bool, default: false
  config_param :num_nodes, :integer, default: 1
  config_param :node_no, :integer, default: 0
  config_param :include_all_message, :bool, default: false
  config_param :exclude_pattern_logfile_elb_name, :string, default: nil
  config_param :use_sqs, :bool, default: true

  def configure(conf)
    super

    if !has_iam_role?
      raise Fluent::ConfigError.new("access_key_id is required") if @access_key_id.nil?
      raise Fluent::ConfigError.new("secret_access_key is required") if @secret_access_key.nil?
    end
    raise Fluent::ConfigError.new("s3_bucketname is required") unless @s3_bucketname
    raise Fluent::ConfigError.new("timestamp_file is required") unless @timestamp_file

    @s3_client = s3_client
    raise Fluent::ConfigError.new("AWS credentials are not available") unless @s3_client
    raise Fluent::ConfigError.new("s3 bucket not found #{@s3_bucketname}") unless s3bucket_is_ok?
  end

  def initialize
    super
    @running = true
  end

  def start
    super

    # files touch
    File.open(@timestamp_file, File::RDWR|File::CREAT).close
    File.open(@buf_file, File::RDWR|File::CREAT).close

    @exclude_pattern_logfile_elb_name_re = Regexp.new(@exclude_pattern_logfile_elb_name) if @exclude_pattern_logfile_elb_name

    Signal.trap('INT') { shutdown }

    refresh_aws_clients!

    if @use_sqs
      input
      setup_sqs_timer
    else
      setup_input_timer
    end
  end

  private

  def refresh_aws_clients!
    log.debug "Refreshing AWS credentials"
    new_s3_client = s3_client
    new_sqs_client = @use_sqs ? sqs_client : nil

    unless new_s3_client && (!@use_sqs || new_sqs_client)
      log.warn "AWS credentials refresh skipped; keeping current clients"
      return false
    end

    @s3_client = new_s3_client
    @sqs_client = new_sqs_client if @use_sqs
    true
  end

  def shutdown
    log.debug "shutdown"
    if @running
	@running = false
	if @use_sqs
          log.debug "pausing shutdown for 2x#{@refresh_interval}"
          sleep 2*@refresh_interval
          unset_sqs if @queue_url && @queue_url != ""
        else
    	  log.debug "pausing shutdown for 30 seconds"
          sleep 30
        end
    end
  end

  def setup_sqs_timer
    if @running
      setup_sqs
      return unless @running
      timer_execute(:in_elb_log, @refresh_interval) do
	if @running
	  refresh_aws_clients!
    	  process_sqs
    	  log.debug "sleeping for #{@refresh_interval}"
    	else
    	  if @queue_url && @queue_url != ""
    	    log.debug "Unsetting SQS"
	    unset_sqs
	  end
	end
      end
    end
  end

  def setup_input_timer
    if @running
      timer_execute(:in_elb_log, @refresh_interval) do
	if @running
	    refresh_aws_clients!
    	    input
	    log.debug "sleeping input for #{@refresh_interval}"
	end
      end
    end
  end

  def has_iam_role?
    begin
      ec2 = Aws::EC2::Client.new(aws_client_options)
      aws_credentials_available?(ec2)
    rescue => e
      log.warn "EC2 Client error occurred: #{e.message}"
      @running = false
    end
  end

  def setup_sqs
    begin
    timestamp = Time.now.to_i
    queue_name = "fluent-plugin-elb-log-#{timestamp}"

    sts_client = sts_client()
    return @running = false unless sts_client

    account_id = sts_client.get_caller_identity.account

    queue_policy = {
      "Version": "2012-10-17",
      "Id": "__default_policy_ID",
      "Statement": [
        {
          "Sid": "S3_service_publish",
          "Effect": "Allow",
          "Principal": {
            "Service": "s3.amazonaws.com"
          },
          "Action": "SQS:SendMessage",
          "Resource": "arn:aws:sqs:#{@region}:#{account_id}:#{queue_name}",
          "Condition": {
            "StringEquals": {
              "aws:SourceAccount": "#{account_id}"
	    },
            "ArnLike": {
    	      "aws:SourceArn": "arn:aws:s3:*:*:#{@s3_bucketname}"
	    }
          }
        }
      ]
    }.to_json
    create_queue_response = @sqs_client.create_queue(queue_name: queue_name,
      attributes: {
        'Policy' => queue_policy
      }
    )
    @queue_url = create_queue_response.queue_url
    queue_attributes = @sqs_client.get_queue_attributes(
      queue_url: @queue_url,
      attribute_names: ['QueueArn']
    )
    queue_arn = queue_attributes.attributes['QueueArn']
    log.debug "New SQS queue created: #{queue_arn}"

    notification_configuration = s3_notification_configuration_with_queue(queue_arn)

    @s3_client.put_bucket_notification_configuration(
      bucket: @s3_bucketname,
      notification_configuration: notification_configuration
    )
    log.debug "S3 notification events has been set for #{@s3_bucketname}/#{@s3_prefix}"

    rescue Aws::SQS::Errors::InvalidAttributeValue => e
      log.debug "SQS error: #{e.message}"
      @running = false

    rescue Aws::S3::Errors::InvalidArgument => e
      log.debug "S3 Event error: #{e.message}"
      if @sqs_client
        @sqs_client.delete_queue(queue_url: @queue_url)
        @queue_url = ""
        log.debug "#{queue_arn} deleted"
      end
      @running = false

    rescue Aws::Errors::MissingCredentialsError => e
      log.warn "AWS credentials unavailable while setting up SQS: #{e.message}"
      @running = false

    rescue => e
      log.warn "SQS setup error occurred: #{e.message}"
      @running = false
    end
  end

  def unset_sqs
    return if @queue_url.nil? || @queue_url == ""
    begin
      notification_configuration = s3_notification_configuration_without_queue

      @s3_client.put_bucket_notification_configuration(
        bucket: @s3_bucketname,
        notification_configuration: notification_configuration
      )
      log.debug "S3 notification events has been removed"

      @sqs_client.delete_queue(queue_url: @queue_url)
      log.debug "SQS queue #{@queue_url} has been removed"
      @queue_url = ""
    rescue Aws::Errors::MissingCredentialsError => e
      log.warn "SQS cleanup skipped because AWS credentials are unavailable: #{e.message}"
    rescue => e
      log.warn "SQS cleanup error occurred: #{e.message}"
    end
  end

  def current_s3_notification_configuration
    @s3_client.get_bucket_notification_configuration(bucket: @s3_bucketname).to_h
  end

  def s3_notification_configuration_with_queue(queue_arn)
    notification_configuration = current_s3_notification_configuration
    queue_configurations = existing_s3_notification_queue_configurations(notification_configuration)

    queue_configurations << {
      id: SQS_NOTIFICATION_ID,
      events: ['s3:ObjectCreated:*'],
      queue_arn: queue_arn,
      filter: {
        key: {
          filter_rules: [
            {
              name: 'Prefix',
              value: "#{@s3_prefix}"
            }
          ]
        }
      }
    }

    notification_configuration[:queue_configurations] = queue_configurations
    compact_s3_notification_configuration(notification_configuration)
  end

  def s3_notification_configuration_without_queue
    notification_configuration = current_s3_notification_configuration
    queue_configurations = existing_s3_notification_queue_configurations(notification_configuration)
    notification_configuration[:queue_configurations] = queue_configurations
    compact_s3_notification_configuration(notification_configuration)
  end

  def existing_s3_notification_queue_configurations(notification_configuration)
    notification_configuration
      .fetch(:queue_configurations, [])
      .reject { |queue_configuration| queue_configuration[:id] == SQS_NOTIFICATION_ID }
  end

  def compact_s3_notification_configuration(notification_configuration)
    notification_configuration.each_with_object({}) do |(key, value), compacted_configuration|
      next if value.nil?
      next if value.is_a?(Array) && value.empty?

      compacted_configuration[key] = value
    end
  end

  def get_timestamp_file
    begin
      # get timestamp last proc
      start_time = @start_time ? Time.parse(@start_time).utc : Time.at(0)
      timestamp = start_time.to_i
      log.debug "timestamp file #{@timestamp_file} read"
      File.open(@timestamp_file, File::RDONLY) do |file|
        if file.size > 0
          timestamp_from_file = file.read.to_i
          if timestamp_from_file > timestamp
            timestamp = timestamp_from_file
          end
        end
      end
      log.debug "timestamp start at:" + Time.at(timestamp).to_s
      return timestamp
    rescue => e
      log.warn "timestamp file get and parse error occurred: #{e.message}"
      @running = false
    end
  end

  def put_timestamp_file(timestamp)
    begin
      log.debug "timestamp file #{@timestamp_file} write"
      File.open(@timestamp_file, File::WRONLY|File::CREAT|File::TRUNC) do |file|
        file.puts timestamp.to_s
      end
    rescue => e
      log.warn "timestamp file get and parse error occurred: #{e.message}"
      @running = false
    end
  end

  def s3_client
    build_aws_client(Aws::S3::Client, "S3")
  end

  def s3bucket_is_ok?
    log.debug "searching for bucket #{@s3_bucketname}"

    begin
      # try get one
      !(get_object_list(1).nil?)
    rescue => e
      log.warn "error occurred: #{e.message}"
      @running = false
      false
    end
  end

  def sqs_client
    build_aws_client(Aws::SQS::Client, "SQS")
  end

  def sts_client
    build_aws_client(Aws::STS::Client, "STS")
  end

  def aws_client_options
    options = {
      region: @region,
    }
    if @access_key_id && @secret_access_key
      options[:access_key_id] = @access_key_id
      options[:secret_access_key] = @secret_access_key
    end
    if @http_proxy
      options[:http_proxy] = @http_proxy
    end
    options
  end

  def build_aws_client(client_class, service_name)
    begin
      log.debug "#{service_name} client connect"
      client = client_class.new(aws_client_options)
      unless aws_credentials_available?(client)
        raise Aws::Errors::MissingCredentialsError, "unable to sign request without credentials set"
      end
      client
    rescue Aws::Errors::MissingCredentialsError => e
      log.warn "#{service_name} Client credentials unavailable: #{e.message}"
      nil
    rescue => e
      log.warn "#{service_name} Client error occurred: #{e.message}"
      nil
    end
  end

  def aws_credentials_available?(client)
    credentials = client.config.credentials
    return false unless credentials

    resolved_credentials = credentials.respond_to?(:credentials) ? credentials.credentials : credentials
    resolved_credentials.respond_to?(:set?) && resolved_credentials.set?
  rescue Aws::Errors::MissingCredentialsError
    false
  end

  def input
    begin
      log.debug "input start"
      timestamp = get_timestamp_file()

      object_keys = get_object_keys(timestamp)
      object_keys = sort_object_key(object_keys)

      log.info "found #{object_keys.count} new object(s)."

      object_keys.each do |object_key|
        record_common = {
          "account_id" => object_key[:account_id],
          "region" => object_key[:region],
          "logfile_date" => object_key[:logfile_date],
          "logfile_elb_name" => object_key[:logfile_elb_name],
          "elb_ip_address" => object_key[:elb_ip_address],
          "logfile_hash" => object_key[:logfile_hash],
          "logfile_timestamp" => object_key[:logfile_timestamp],
          "key" => object_key[:key],
          "prefix" => object_key[:prefix],
          "logfile_timestamp_unixtime" => object_key[:logfile_timestamp_unixtime],
          "s3_last_modified_unixtime" => object_key[:s3_last_modified_unixtime],
        }

        get_file_from_s3(object_key[:key])
        emit_lines_from_buffer_file(record_common)

        put_timestamp_file(object_key[:s3_last_modified_unixtime])

        if @delete
          delete_file_from_s3(object_key[:key])
        end
      end
    rescue Aws::Errors::MissingCredentialsError => e
      log.warn "AWS credentials unavailable while reading S3: #{e.message}"
    rescue => e
      log.warn "error occurred: #{e.message}"
      @running = false
    end
  end

  def process_sqs
    begin
      if @running
        number_of_messages = @sqs_client.get_queue_attributes(
          queue_url: @queue_url,
          attribute_names: ["ApproximateNumberOfMessages"]
        ).attributes["ApproximateNumberOfMessages"].to_i

	count = 0
	while count < number_of_messages
	    messages = @sqs_client.receive_message(
    	      queue_url: @queue_url,
              max_number_of_messages: 10,
              wait_time_seconds: 10
    	    ).messages
    	    log.debug "SQS queue has ApproximateNumberOfMessages=#{number_of_messages}" if number_of_messages > 0

	    break if messages.empty?

    	    messages.each do |message|
    	      count += 1
    	      s3_event = JSON.parse(message.body)
              unless s3_event.key?('Records')
        	@sqs_client.delete_message(
                 queue_url: @queue_url,
                 receipt_handle: message.receipt_handle
	        )
	        next
	      end
              #log.debug "S3 event: #{s3_event}"
              s3_event['Records'].each do |record|
                next unless record['s3']

                bucket = record['s3']['bucket']['name']
                next unless bucket == @s3_bucketname

                key = CGI.unescape(record['s3']['object']['key'])
                event_time = Time.parse(record['eventTime']).to_i
                log.debug "S3 event received for #{key} at #{record['eventTime']}"

                object_key = get_object_key(key, event_time, 0)
                next if object_key.nil?

                record_common = {
                  "account_id" => object_key[:account_id],
                  "region" => object_key[:region],
                  "logfile_date" => object_key[:logfile_date],
                  "logfile_elb_name" => object_key[:logfile_elb_name],
                  "elb_ip_address" => object_key[:elb_ip_address],
                  "logfile_hash" => object_key[:logfile_hash],
                  "logfile_timestamp" => object_key[:logfile_timestamp],
                  "key" => object_key[:key],
                  "prefix" => object_key[:prefix],
                  "logfile_timestamp_unixtime" => object_key[:logfile_timestamp_unixtime],
                  "s3_last_modified_unixtime" => object_key[:s3_last_modified_unixtime],
                }

                get_file_from_s3(object_key[:key])
                emit_lines_from_buffer_file(record_common)

                put_timestamp_file(object_key[:s3_last_modified_unixtime])

                if @delete
                  delete_file_from_s3(object_key[:key])
                end
              end


              @sqs_client.delete_message(
               queue_url: @queue_url,
               receipt_handle: message.receipt_handle
              )
    	    end
    	    if count == 0
    		log.debug "No messages out of #{number_of_messages} were processed - should never happen"
    		break
    	    end
        end
      end
      rescue Aws::Errors::MissingCredentialsError => e
        log.warn "AWS credentials unavailable while reading SQS: #{e.message}"
      rescue => e
        log.warn "error occurred: #{e.message}"
        @running = false
    end
  end

  def sort_object_key(src_object_keys)
    begin
      src_object_keys.sort do |a, b|
        a[:s3_last_modified_unixtime] <=> b[:s3_last_modified_unixtime]
      end
    rescue => e
      log.warn "error occurred: #{e.message}"
      @running = false
    end
  end

  def get_object_list(max_num)
    @s3_client.list_objects(
      bucket: @s3_bucketname,
      max_keys: max_num,
      prefix: @s3_prefix
    )
  end

  def get_object_key(key, last_modified, timestamp)
    node_no = Digest::SHA1.hexdigest(key).to_i(16) % @num_nodes
    return nil unless node_no == @node_no

    matches = LOGFILE_REGEXP.match(key)

    s3_last_modified_unixtime = last_modified
    if s3_last_modified_unixtime > timestamp and matches
      if @exclude_pattern_logfile_elb_name_re && @exclude_pattern_logfile_elb_name_re.match(matches[:logfile_elb_name])
        log.debug "Skipping object #{key} b/c it matches exclude_pattern_logfile_elb_name"
        return nil
      end

      object_key = {
        key: key,
        prefix: matches[:prefix],
        account_id: matches[:account_id],
        region: matches[:region],
        logfile_date: matches[:logfile_date],
        logfile_elb_name: matches[:logfile_elb_name],
        logfile_timestamp: matches[:logfile_timestamp],
        elb_ip_address: matches[:elb_ip_address],
        logfile_hash: matches[:logfile_hash],
        logfile_timestamp_unixtime: Time.parse(matches[:logfile_timestamp]).to_i,
        s3_last_modified_unixtime: s3_last_modified_unixtime,
      }
    end

    return object_key
  end

  def get_object_keys(timestamp)
    object_keys = []

    resp = @s3_client.list_objects_v2(
      bucket: @s3_bucketname,
      prefix: @s3_prefix
    )

    while @running do
      resp.contents.each do |content|
        log.debug "Getting #{content.key}"
        object_key = get_object_key(content.key, content.last_modified.to_i, timestamp)
        next if object_key.nil?
        object_keys << object_key
      end

      if !resp.is_truncated
        return object_keys
      end

      resp = @s3_client.list_objects_v2(
        bucket: @s3_bucketname,
        prefix: @s3_prefix,
        continuation_token: resp.next_continuation_token
      )
    end

    return object_keys
  end

  def inflate(srcfile, dstfile)
    File.open(dstfile, File::WRONLY|File::CREAT|File::TRUNC) do |bfile|
      File.open(srcfile) do |file|
        zio = file
        loop do
          io = Zlib::GzipReader.new zio
          bfile.write io.read
          unused = io.unused
          io.finish
          break if unused.nil?
          zio.pos -= unused.length
        end
      end
    end
  end

  def get_file_from_s3(object_name)
    begin
      log.debug "retrieving #{object_name}"

      Tempfile.create('fluent-elblog') do |tfile|
        @s3_client.get_object(bucket: @s3_bucketname, key: object_name, response_target: tfile.path)

        if File.extname(object_name) != '.gz'
          FileUtils.cp(tfile.path, @buf_file)
        else
          inflate(tfile.path, @buf_file)
        end
      end
    rescue => e
      log.warn "error occurred: #{e.message}, #{e.backtrace}"
      @running = false
    end
  end

  def delete_file_from_s3(object_name)
    begin
      log.debug "deleting object from s3 name is #{object_name}"

      @s3_client.delete_object(bucket: @s3_bucketname, key: object_name)
    rescue => e
      log.warn "error occurred: #{e.message}, #{e.backtrace}"
    end
  end

  def emit_lines_from_buffer_file(record_common)
    begin
      # emit per line
      File.open(@buf_file, File::RDONLY) do |file|
        file.each_line do |line|
          line_match = ACCESSLOG_REGEXP.match(line)
          unless line_match
            log.info "nomatch log found: #{line} in #{record_common['key']}"
            next
          end

          now = Fluent::Engine.now
          time = Time.parse(line_match[:time]).to_i rescue now

          router.emit(
            @tag,
            time,
            record_common
              .merge(format_record(line_match)
              .merge(@include_all_message ? {"all_message" => line} : {})
            )
          )
        end
      end
    rescue => e
      log.warn "error occurred: #{e.message}"
      @running = false
    end
  end

  def format_record(item)
    { "time" => item[:time].gsub(/Z/, '+0000'),
      "elb" => item[:elb],
      "client" => item[:client],
      "client_port" => item[:client_port],
      "target" => item[:target],
      "target_port" => item[:target_port],
      "request_processing_time" => item[:request_processing_time].to_f,
      "target_processing_time" => item[:target_processing_time].to_f,
      "response_processing_time" => item[:response_processing_time].to_f,
      "elb_status_code" => item[:elb_status_code],
      "target_status_code" => item[:target_status_code],
      "received_bytes" => item[:received_bytes].to_i,
      "sent_bytes" => item[:sent_bytes].to_i,
      "request_method" => item[:request_method],
      "request_uri" => item[:request_uri],
      "request_protocol" => item[:request_protocol],
      "user_agent" => item[:user_agent],
      "ssl_cipher" => item[:ssl_cipher],
      "ssl_protocol" => item[:ssl_protocol],
      "type" => item[:type],
      "target_group_arn" => item[:target_group_arn],
      "trace_id" => item[:trace_id],
      "domain_name" => item[:domain_name],
      "chosen_cert_arn" => item[:chosen_cert_arn],
      "matched_rule_priority" => item[:matched_rule_priority],
      "request_creation_time" => item[:request_creation_time],
      "actions_executed" => item[:actions_executed],
      "redirect_url" => item[:redirect_url],
      "error_reason" => item[:error_reason],
      "target_port_list" => item[:target_port_list],
      "target_status_code_list" => item[:target_status_code_list],
      "classification" => item[:classification],
      "classification_reason" => item[:classification_reason],
      "conn_trace_id" => item[:conn_trace_id]
    }
  end
end
