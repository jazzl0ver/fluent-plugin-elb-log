# Amazon ELB log input plugin for fluentd

[![Gem Version](https://badge.fury.io/rb/fluent-plugin-elb-log.svg)](https://badge.fury.io/rb/fluent-plugin-elb-log)
[![Build Status](https://travis-ci.org/shinsaka/fluent-plugin-elb-log.svg?branch=master)](https://travis-ci.org/shinsaka/fluent-plugin-elb-log)
[![Code Climate](https://codeclimate.com/github/shinsaka/fluent-plugin-elb-log/badges/gpa.svg)](https://codeclimate.com/github/shinsaka/fluent-plugin-elb-log)
[![Test Coverage](https://codeclimate.com/github/shinsaka/fluent-plugin-elb-log/badges/coverage.svg)](https://codeclimate.com/github/shinsaka/fluent-plugin-elb-log/coverage)

## Overview
- Amazon Web Services ELB log input plubin for fluentd

## Requirements

| fluent-plugin-elb-log | fluentd    | ruby   |
|-----------------------|------------|--------|
| >= 0.3.0              | >= v0.14.0 | >= 2.1 |
| < 0.3.0               | >= v0.12.0 | >= 1.9 |

## Installation

    $ fluentd-gem fluent-plugin-elb-log

## AWS ELB Settings
- settings see: [Elastic Load Balancing](http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/enable-access-logs.html)
- developer guide: [](http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/access-log-collection.html)

## Different from version 0.4.x
- Using version 3 of the AWS SDK for Ruby.

## Support Application Load Balancer (ver 0.4.0 or later)
- Support Access Logs for Application Load Balancer
 - https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
- Existing ELB is called Classic Load Balancer
 - http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/access-log-collection.html

## When SSL certification error
log:
```
SSL_connect returned=1 errno=0 state=SSLv3 read server certificate B: certificate verify failed
```
Do env setting follows:
```
SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt (If you using amazon linux)
```

## Configuration

```config
<source>
  @type elb_log

  # following attibutes are required
  region            <region name>
  s3_bucketname     <bucketname>
  s3_prefix         <elb log's prefix>
  timestamp_file    <proc last file timestamp record filename>
  buf_file          <buffer file path>
  refresh_interval  <interval number by second>
  tag               <tag name(default: elb.access)>
  delete            <boolean delete processed log files from S3(default: false)>
  include_all_message <boolean (default:false)>
  start_time        <last timestamp to start from>
  exclude_pattern_logfile_elb_name <exclude pattern for logfile_elb_name key>
  use_sqs           <boolean use SQS polling instead of iteratively processing the whole bucket>

  # following attibutes are required if you don't use IAM Role
  access_key_id     <access_key>
  secret_access_key <secret_access_key>
</source>
```

`use_sqs` automatically creates an SQS queue named `fluent-plugin-elb-log-<current_timestamp>` 
and sets up the `all object create event` S3 event notification for the chosen S3 bucket. Stopping fluentd deletes both autmatically.
To make it work, the following IAM policy should be attached to the instance IAM role or the user:
```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "FluentdPermissions",
            "Effect": "Allow",
            "Action": [
                "sqs:DeleteMessage",
                "s3:GetObject",
                "sqs:ReceiveMessage",
                "sqs:DeleteQueue",
                "sqs:GetQueueAttributes",
                "s3:ListBucket",
                "s3:PutBucketNotification",
                "sqs:CreateQueue"
            ],
            "Resource": [
                "arn:aws:sqs:*:123456789012:fluent-plugin-elb-log-*",
                "arn:aws:s3:::alb-logs-bucket/*",
                "arn:aws:s3:::alb-logs-bucket"
            ]
        }
    ]
}
```
When `use_sqs` is false:
  - 300 seconds is a good value for the `refresh_interval`
  - the plugin executes processing the whole S3 bucket (with the respect of `s3_prefix` and `start_time`/`timestamp_file`) every `refresh_interval`

When `use_sqs` is true:
  - `refresh_interval` of 30-60 seconds should be fine.
  - the plugin executes processing the whole S3 bucket (with the respect of `s3_prefix` and `start_time`/`timestamp_file`) only once (at start) and then 
polls the SQS queue every `refresh_interval`.

### Example setting
```config
<source>
  @type elb_log
  region            us-east-1
  s3_bucketname     my-elblog-bucket
  s3_prefix         prodcution/web
  timestamp_file    /tmp/elb_last_at.dat
  buf_file          /tmp/fluentd-elblog.tmpfile
  refresh_interval  30
  tag               elb.access
  delete            false
  include_all_message false
  exclude_pattern_logfile_elb_name "^app\.(uat|qa)\."
  start_time        2025-02-27T10:45:00
  use_sqs           true
  access_key_id     XXXXXXXXXXXXXXXXXXXX
  secret_access_key xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
</source>

<filter elb.access>
  @type record_transformer
  <record>
    timestamp ${record["request_creation_time"]}
    logfile_name ${record["key"]}
  </record>
  remove_keys prefix,logfile_date,logfile_elb_name,logfile_hash,logfile_timestamp,logfile_timestamp_unixtime,key,time,s3_last_modified_unixtime
</filter>

<match elb.access>
#  @type stdout
  @type opensearch
  hosts node-1,node-2,node-3
  port 9200
  scheme https
  logstash_format true
  logstash_prefix alb-logs
  user fluentd
  password secret
  ssl_verify true
  ca_file /etc/fluentd/root-ca.pem
  flush_interval 300s
</match>
```

### json output example
```json
{
    "account_id":"123456789012",
    "region":"ap-northeast-1",
    "logfile_date":"2015/06/15",
    "logfile_elb_name":"my-elb-name",
    "elb_ip_address":"52.0.0.0",
    "logfile_hash":"12squv5w",
    "logfile_timestamp":"20150615T0400Z",
    "key":"TEST/AWSLogs/123456789012/elasticloadbalancing/ap-northeast-1/2015/06/15/123456789012_elasticloadbalancing_ap-northeast-1_my-elb-name_20150615T0400Z_52.68.215.138_69squv5w.log",
    "prefix":"TEST",
    "elb_timestamp_unixtime":1434340800,
    "time":"2015-06-15T03:47:12.728427+0000",
    "elb":"my-elb-name",
    "client":"54.1.1.1",
    "client_port":"43759",
    "target":"10.0.0.1",
    "target_port":"80",
    "request_processing_time":4.0e-05,
    "target_processing_time":0.105048,
    "response_processing_time":2.4e-05,
    "elb_status_code":"200",
    "target_status_code":"200",
    "received_bytes":0,
    "sent_bytes":4622,
    "request_method":"GET",
    "request_uri":"https://my-elb-test.example.com/",
    "request_protocol":"HTTP/1.1",
    "user_agent":"Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "ssl_cipher":"DHE-RSA-AES128-SHA",
    "ssl_protocol":"TLSv1.2",
    "type":"http",
    "target_group_arn": "arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:targetgroup/lbgrp1/605122a4e4ee9f2d",
    "trace_id": "\"Root=1-xxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxx\"",
    "domain_name": "-",
    "chosen_cert_arn": "-",
    "matched_rule_priority": "0",
    "request_creation_time": "2099-10-26T06:10:03.050000Z",
    "actions_executed": "forward",
    "redirect_url": "-",
    "error_reason": "-",
    "target_port_list": "\"192.168.0.1:443\"",
    "target_status_code_list": "\"301\"",
    "classification": "-",
    "classification_reason": "-",
    "conn_trace_id": "TID_xxxxxxxxxxxxxxxxxxxxxxx"
}
```
