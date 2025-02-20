require_relative '../helper'

class Elb_LogInputTest < Test::Unit::TestCase

  def setup
    Fluent::Test.setup
  end

  DEFAULT_CONFIG = {
    access_key_id: 'dummy_access_key_id',
    secret_access_key: 'dummy_secret_access_key',
    s3_endpoint: 's3.ap-northeast-1.amazonaws.com',
    s3_bucketname: 'dummy_bucket',
    s3_prefix: 'test',
    region: 'ap-northeast-1',
    timestamp_file: 'elb_last_at.dat',
    refresh_interval: 300
  }

  def parse_config(conf = {})
    ''.tap{|s| conf.each { |k, v| s << "#{k} #{v}\n" } }
  end

  def create_driver(conf = DEFAULT_CONFIG)
    Fluent::Test::Driver::Input.new(Fluent::Plugin::Elb_LogInput).configure(parse_config conf)
  end

  def iam_info_url
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
  end

  def use_iam_role
    stub_request(:get, iam_info_url)
      .to_return(status: [200, 'OK'], body: "hostname")
    stub_request(:get, "#{iam_info_url}hostname")
      .to_return(status: [200, 'OK'],
                 body: {
                   "AccessKeyId" => "dummy",
                   "SecretAccessKey" => "secret",
                   "Token" => "token"
                 }.to_json)
  end

  def iam_info_timeout
    stub_request(:get, iam_info_url).to_timeout
  end

  def not_use_iam_role
    stub_request(:get, iam_info_url)
      .to_return(status: [404, 'Not Found'])
  end

  def s3bucket_ok
    stub_request(:get, 'https://s3.ap-northeast-1.amazonaws.com/dummy_bucket?encoding-type=url&max-keys=1&prefix=test')
      .to_return(status: 200, body: "", headers: {})
    stub_request(:get, 'https://s3-ap-northeast-1.amazonaws.com/dummy_bucket?encoding-type=url&max-keys=1&prefix=test')
      .to_return(status: 200, body: "", headers: {})
  end

  def s3bucket_not_found
    stub_request(:get, 'https://s3.ap-northeast-1.amazonaws.com/dummy_bucket?encoding-type=url&max-keys=1&prefix=test')
      .to_return(status: 404, body: "", headers: {})
    stub_request(:get, 'https://s3-ap-northeast-1.amazonaws.com/dummy_bucket?encoding-type=url&max-keys=1&prefix=test')
      .to_return(status: 404, body: "", headers: {})
  end

  def test_configure_default
    s3bucket_ok
    use_iam_role
    assert_nothing_raised { create_driver }

    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:s3_bucketname)
      create_driver(conf)
    }
    assert_equal('s3_bucketname is required', exception.message)

    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:timestamp_file)
      create_driver(conf)
    }
    assert_equal('timestamp_file is required', exception.message)
  end

  def test_configure_in_EC2_with_IAM_role
    s3bucket_ok
    use_iam_role
    conf = DEFAULT_CONFIG.clone
    conf.delete(:access_key_id)
    conf.delete(:secret_access_key)
    assert_nothing_raised { create_driver(conf) }
  end

  def test_configure_in_EC2_without_IAM_role
    ENV['AWS_PROFILE'] = ''
    exception = assert_raise(Fluent::ConfigError) {
      s3bucket_ok
      not_use_iam_role
      conf = DEFAULT_CONFIG.clone
      conf.delete(:access_key_id)
      create_driver(conf)
    }
    assert_equal('access_key_id is required', exception.message)

    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:secret_access_key)
      create_driver(conf)
    }
    assert_equal('secret_access_key is required', exception.message)
  end

  def test_configure_outside_EC2
    s3bucket_ok
    iam_info_timeout

    assert_nothing_raised { create_driver }
    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:access_key_id)
      create_driver(conf)
    }
    assert_equal('access_key_id is required', exception.message)

    exception = assert_raise(Fluent::ConfigError) {
      conf = DEFAULT_CONFIG.clone
      conf.delete(:secret_access_key)
      create_driver(conf)
    }
    assert_equal('secret_access_key is required', exception.message)
  end

  def test_not_found_s3bucket
    e = assert_raise(Fluent::ConfigError) {
      use_iam_role
      s3bucket_not_found
      create_driver(DEFAULT_CONFIG.clone)
    }
    assert_equal('s3 bucket not found dummy_bucket', e.message)
  end

  def test_logfilename_classic_lb_parse
    logfile_classic = 'classic/AWSLogs/123456789012/elasticloadbalancing/ap-northeast-1/2017/05/03/123456789012_elasticloadbalancing_ap-northeast-1_elbname_20170503T1250Z_10.0.0.1_43nzjpdj.log'

    m = Fluent::Plugin::Elb_LogInput::LOGFILE_REGEXP.match(logfile_classic)
    assert_equal('classic', m[:prefix])
    assert_equal('123456789012', m[:account_id])
    assert_equal('ap-northeast-1', m[:region])
    assert_equal('2017/05/03', m[:logfile_date])
    assert_equal('elbname', m[:logfile_elb_name])
    assert_equal('20170503T1250Z', m[:elb_timestamp])
    assert_equal('10.0.0.1', m[:elb_ip_address])
    assert_equal('43nzjpdj', m[:logfile_hash])
  end

  def test_logfilename_appication_lb_parse
    logfile_applb = 'applb/AWSLogs/123456789012/elasticloadbalancing/ap-northeast-1/2017/05/03/123456789012_elasticloadbalancing_ap-northeast-1_app.elbname.59bfa19e900030c2_20170503T1310Z_10.0.0.1_2tko12gv.log.gz'

    m = Fluent::Plugin::Elb_LogInput::LOGFILE_REGEXP.match(logfile_applb)
    assert_equal('applb', m[:prefix])
    assert_equal('123456789012', m[:account_id])
    assert_equal('ap-northeast-1', m[:region])
    assert_equal('2017/05/03', m[:logfile_date])
    assert_equal('app.elbname.59bfa19e900030c2', m[:logfile_elb_name])
    assert_equal('20170503T1310Z', m[:logfile_timestamp])
    assert_equal('10.0.0.1', m[:elb_ip_address])
    assert_equal('2tko12gv', m[:logfile_hash])
  end

  def test_log_classic_lb_parse
    log = '2017-05-05T12:53:50.128456Z elbname 10.11.12.13:37852 192.168.30.186:443 0.00004 0.085372 0.000039 301 301 0 0 "GET https://elbname-123456789.ap-northeast-1.elb.amazonaws.com:443/ HTTP/1.1" "curl/7.51.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2'

    m = Fluent::Plugin::Elb_LogInput::ACCESSLOG_REGEXP.match(log)
    assert_equal('2017-05-05T12:53:50.128456Z', m[:time])
    assert_equal('elbname', m[:elb])
    assert_equal('10.11.12.13', m[:client])
    assert_equal('37852', m[:client_port])
    assert_equal('192.168.30.186', m[:target])
    assert_equal('443', m[:target_port])
    assert_equal('0.00004', m[:request_processing_time])
    assert_equal('0.085372', m[:target_processing_time])
    assert_equal('0.000039', m[:response_processing_time])
    assert_equal('301', m[:elb_status_code])
    assert_equal('301', m[:target_status_code])
    assert_equal('0', m[:received_bytes])
    assert_equal('0', m[:sent_bytes])
    assert_equal('GET', m[:request_method])
    assert_equal('https://elbname-123456789.ap-northeast-1.elb.amazonaws.com:443/', m[:request_uri])
    assert_equal('HTTP/1.1', m[:request_protocol])
    assert_equal('curl/7.51.0', m[:user_agent])
    assert_equal('ECDHE-RSA-AES128-GCM-SHA256', m[:ssl_cipher])
    assert_equal('TLSv1.2', m[:ssl_protocol])
    assert_equal(nil, m[:type])
    assert_equal(nil, m[:target_group_arn])
    assert_equal(nil, m[:trace_id])
    assert_equal(nil, m[:conn_trace_id])
  end

  def test_log_application_lb_parse
    log = 'https 2017-05-05T13:07:53.468529Z app/elbname/59bfa19e900030c2 10.20.30.40:52730 192.168.30.186:443 0.006 0.000 0.086 301 301 117 507 "GET https://elbname-1121128512.ap-northeast-1.elb.amazonaws.com:443/ HTTP/1.1" "curl/7.51.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:targetgroup/lbgrp1/605122a4e4ee9f2d "Root=1-590c7929-4eb4cb393d46a01d22db8473"'

    m = Fluent::Plugin::Elb_LogInput::ACCESSLOG_REGEXP.match(log)
    assert_equal('2017-05-05T13:07:53.468529Z', m[:time])
    assert_equal('app/elbname/59bfa19e900030c2', m[:elb])
    assert_equal('10.20.30.40', m[:client])
    assert_equal('52730', m[:client_port])
    assert_equal('192.168.30.186', m[:target])
    assert_equal('443', m[:target_port])
    assert_equal('0.006', m[:request_processing_time])
    assert_equal('0.000', m[:target_processing_time])
    assert_equal('0.086', m[:response_processing_time])
    assert_equal('301', m[:elb_status_code])
    assert_equal('301', m[:target_status_code])
    assert_equal('117', m[:received_bytes])
    assert_equal('507', m[:sent_bytes])
    assert_equal('GET', m[:request_method])
    assert_equal('https://elbname-1121128512.ap-northeast-1.elb.amazonaws.com:443/', m[:request_uri])
    assert_equal('HTTP/1.1', m[:request_protocol])
    assert_equal('curl/7.51.0', m[:user_agent])
    assert_equal('ECDHE-RSA-AES128-GCM-SHA256', m[:ssl_cipher])
    assert_equal('TLSv1.2', m[:ssl_protocol])
    assert_equal('https', m[:type])
    assert_equal('arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:targetgroup/lbgrp1/605122a4e4ee9f2d', m[:target_group_arn])
    assert_equal('"Root=1-590c7929-4eb4cb393d46a01d22db8473"', m[:trace_id])
    assert_equal(nil, m[:conn_trace_id])
  end

  def test_grp_and_trace_fileld
    log = 'http 2018-03-15T03:50:00.337397Z app/elbname/aabbccdd9988 10.248.9.92:54000 10.248.9.77:80 0.001 0.002 0.003 200 200 686 6476 "GET http://services-lb.nottherealsite.net:80/svc/example HTTP/1.1" "-" - - arn:aws:elasticloadbalancing:us-east-1:123456789123:targetgroup/example-service/1234abcd1234abcd "Root=1-xxxxxxxx-yyyyyyyyyyyyyyyyyyyzzzzz" "-" "-" 3'
    m = Fluent::Plugin::Elb_LogInput::ACCESSLOG_REGEXP.match(log)
    assert_equal('http', m[:type])
    assert_equal('2018-03-15T03:50:00.337397Z', m[:time])
    assert_equal('app/elbname/aabbccdd9988', m[:elb])
    assert_equal('10.248.9.92', m[:client])
    assert_equal('54000', m[:client_port])
    assert_equal('10.248.9.77', m[:target])
    assert_equal('80', m[:target_port])
    assert_equal('0.001', m[:request_processing_time])
    assert_equal('0.002', m[:target_processing_time])
    assert_equal('0.003', m[:response_processing_time])
    assert_equal('200', m[:elb_status_code])
    assert_equal('200', m[:target_status_code])
    assert_equal('686', m[:received_bytes])
    assert_equal('6476', m[:sent_bytes])
    assert_equal('GET', m[:request_method])
    assert_equal('http://services-lb.nottherealsite.net:80/svc/example', m[:request_uri])
    assert_equal('HTTP/1.1', m[:request_protocol])
    assert_equal('-', m[:user_agent])
    assert_equal('-', m[:ssl_cipher])
    assert_equal('-', m[:ssl_protocol])
    assert_equal('arn:aws:elasticloadbalancing:us-east-1:123456789123:targetgroup/example-service/1234abcd1234abcd', m[:target_group_arn])
    assert_equal('"Root=1-xxxxxxxx-yyyyyyyyyyyyyyyyyyyzzzzz"', m[:trace_id])
    assert_equal('domain_name', m[:domain_name])
    assert_equal('chosen_cert_arn', m[:chosen_cert_arn])
    assert_equal('matched_rule_priority', m[:matched_rule_priority])
  end

  def test_alb_all_field
    log = 'http 2019-10-26T06:10:03.157333Z app/my-alb/520e61ffffffffff 60.11.22.33:51306 192.168.30.111:443 0.010 0.097 0.001 301 301 414 507 "GET http://www.example.com:80/ HTTP/1.1" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36" ssl1 ssl2 arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:targetgroup/lbgrp1/605122a4ffffffff "Root=1-123abcde-d03aafc8497211546b64c54c" "domainname" "certarn" 50000 2019-10-26T06:10:03.050000Z "forward" "redirect://url-something.com/" "error_reason" "192.168.30.186:443" "301"'
    m = Fluent::Plugin::Elb_LogInput::ACCESSLOG_REGEXP.match(log)
    assert_equal('http', m[:type])
    assert_equal('2019-10-26T06:10:03.157333Z', m[:time])

    assert_equal('app/my-alb/520e61ffffffffff', m[:elb])
    assert_equal('60.11.22.33', m[:client])
    assert_equal('51306', m[:client_port])
    assert_equal('192.168.30.111', m[:target])
    assert_equal('443', m[:target_port])

    assert_equal('0.010', m[:request_processing_time])
    assert_equal('0.097', m[:target_processing_time])
    assert_equal('0.001', m[:response_processing_time])
    assert_equal('301', m[:elb_status_code])
    assert_equal('301', m[:target_status_code])
    assert_equal('414', m[:received_bytes])
    assert_equal('507', m[:sent_bytes])
    assert_equal('GET', m[:request_method])
    assert_equal('http://www.example.com:80/', m[:request_uri])
    assert_equal('HTTP/1.1', m[:request_protocol])
    assert_equal('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36', m[:user_agent])
    assert_equal('ssl1', m[:ssl_cipher])
    assert_equal('ssl2', m[:ssl_protocol])
    assert_equal('arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:targetgroup/lbgrp1/605122a4ffffffff', m[:target_group_arn])
    assert_equal('"Root=1-123abcde-d03aafc8497211546b64c54c"', m[:trace_id])
    assert_equal('domainname', m[:domain_name])
    assert_equal('certarn', m[:chosen_cert_arn])
    assert_equal('50000', m[:matched_rule_priority])
    assert_equal('2019-10-26T06:10:03.050000Z', m[:request_creation_time])
    assert_equal('forward', m[:actions_executed])
    assert_equal('redirect://url-something.com/', m[:redirect_url])
    assert_equal('error_reason', m[:error_reason])
    assert_equal('"192.168.30.186:443"', m[:target_port_list])
    assert_equal('"301"', m[:target_status_code_list])
    assert_equal(nil, m[:classification])
  end
end
