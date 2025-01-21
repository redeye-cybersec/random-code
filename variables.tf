#########################################
# Variables
#########################################
variable "region" {
  type    = string
  default = "us-east-1"
}

variable "account_id" {
  type = string
}

variable "lambda_s3_bucket" {
  type = string
}

variable "ip_enforcement_lambda_s3_key" {
  type = string
}

variable "stream_processor_lambda_s3_key" {
  type = string
}

variable "table_name" {
  type    = string
  default = "IPSecurityControl"
}

variable "sns_topic_arn" {
  type = string
}

variable "s3_logging_bucket" {
  type = string
}

variable "ip_enforcement_lambda_name" {
  type    = string
  default = "IPEnforcementLambda"
}

variable "stream_processor_lambda_name" {
  type    = string
  default = "IPStreamProcessorLambda"
}

#########################################
# DynamoDB Table with Streams
#########################################
resource "aws_dynamodb_table" "ip_table" {
  name           = var.table_name
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "PrivateIP"
  stream_enabled = true
  stream_view_type = "NEW_AND_OLD_IMAGES"

  attribute {
    name = "PrivateIP"
    type = "S"
  }

  tags = {
    Name = var.table_name
  }
}

#########################################
# IAM Role & Policy for IP Enforcement Lambda
#########################################
data "aws_iam_policy_document" "ip_enforcement_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ip_enforcement_role" {
  name               = var.ip_enforcement_lambda_name
  assume_role_policy = data.aws_iam_policy_document.ip_enforcement_assume_role.json
}

data "aws_iam_policy_document" "ip_enforcement_policy_doc" {
  statement {
    sid       = "AllowDDB"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Scan"]
    resources = [aws_dynamodb_table.ip_table.arn]
  }

  statement {
    sid       = "AllowEC2Terminate"
    actions   = ["ec2:TerminateInstances"]
    resources = ["*"]
  }

  statement {
    sid       = "AllowSNSPublish"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }

  statement {
    sid       = "AllowS3Logging"
    actions   = ["s3:PutObject"]
    resources = [
      "arn:aws:s3:::${var.s3_logging_bucket}",
      "arn:aws:s3:::${var.s3_logging_bucket}/*"
    ]
  }

  statement {
    sid       = "AllowCWLogs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "ip_enforcement_policy" {
  name        = "${var.ip_enforcement_lambda_name}-policy"
  description = "Permissions for IP Enforcement Lambda"
  policy      = data.aws_iam_policy_document.ip_enforcement_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "ip_enforcement_attach" {
  role       = aws_iam_role.ip_enforcement_role.name
  policy_arn = aws_iam_policy.ip_enforcement_policy.arn
}

#########################################
# IAM Role & Policy for Streams Processor Lambda
#########################################
data "aws_iam_policy_document" "stream_processor_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "stream_processor_role" {
  name               = var.stream_processor_lambda_name
  assume_role_policy = data.aws_iam_policy_document.stream_processor_assume_role.json
}

data "aws_iam_policy_document" "stream_processor_policy_doc" {
  statement {
    sid = "AllowDDBStreamRead"
    actions = [
      "dynamodb:DescribeStream",
      "dynamodb:GetRecords",
      "dynamodb:GetShardIterator",
      "dynamodb:ListStreams"
    ]
    resources = ["*"]
  }

  statement {
    sid       = "AllowSNSPublish"
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }

  statement {
    sid       = "AllowS3Put"
    actions   = ["s3:PutObject"]
    resources = [
      "arn:aws:s3:::${var.s3_logging_bucket}",
      "arn:aws:s3:::${var.s3_logging_bucket}/*"
    ]
  }

  statement {
    sid       = "AllowCWLogs"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "stream_processor_policy" {
  name        = "${var.stream_processor_lambda_name}-policy"
  description = "Permissions for Streams Processor Lambda"
  policy      = data.aws_iam_policy_document.stream_processor_policy_doc.json
}

resource "aws_iam_role_policy_attachment" "stream_processor_attach" {
  role       = aws_iam_role.stream_processor_role.name
  policy_arn = aws_iam_policy.stream_processor_policy.arn
}

#########################################
# Lambda: IP Enforcement
#########################################
resource "aws_lambda_function" "ip_enforcement_lambda" {
  function_name = var.ip_enforcement_lambda_name
  role          = aws_iam_role.ip_enforcement_role.arn
  handler       = "ip_enforcement_lambda.lambda_handler"
  runtime       = "python3.9"

  s3_bucket = var.lambda_s3_bucket
  s3_key    = var.ip_enforcement_lambda_s3_key

  environment {
    variables = {
      TABLE_NAME    = var.table_name
      SNS_TOPIC_ARN = var.sns_topic_arn
      S3_BUCKET_NAME = var.s3_logging_bucket
    }
  }
}

#########################################
# Lambda Permissions for EventBridge
#########################################
resource "aws_lambda_permission" "allow_run_instances" {
  statement_id  = "AllowEventBridgeRunInstances"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ip_enforcement_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.run_instances_rule.arn
}

resource "aws_lambda_permission" "allow_terminate_instances" {
  statement_id  = "AllowEventBridgeTerminateInstances"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ip_enforcement_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.terminate_instances_rule.arn
}

#########################################
# EventBridge Rule: RunInstances
#########################################
resource "aws_cloudwatch_event_rule" "run_instances_rule" {
  name         = "RunInstancesTrigger"
  description  = "Triggers on RunInstances"
  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["RunInstances"]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "run_instances_target" {
  rule = aws_cloudwatch_event_rule.run_instances_rule.name
  arn  = aws_lambda_function.ip_enforcement_lambda.arn
}

#########################################
# EventBridge Rule: TerminateInstances
#########################################
resource "aws_cloudwatch_event_rule" "terminate_instances_rule" {
  name         = "TerminateInstancesTrigger"
  description  = "Triggers on TerminateInstances"
  event_pattern = <<EOF
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["TerminateInstances"]
  }
}
EOF
}

resource "aws_cloudwatch_event_target" "terminate_instances_target" {
  rule = aws_cloudwatch_event_rule.terminate_instances_rule.name
  arn  = aws_lambda_function.ip_enforcement_lambda.arn
}

#########################################
# Lambda: Streams Processor
#########################################
resource "aws_lambda_function" "ip_stream_processor" {
  function_name = var.stream_processor_lambda_name
  role          = aws_iam_role.stream_processor_role.arn
  handler       = "stream_processor.lambda_handler"
  runtime       = "python3.9"

  s3_bucket = var.lambda_s3_bucket
  s3_key    = var.stream_processor_lambda_s3_key

  environment {
    variables = {
      SNS_TOPIC_ARN = var.sns_topic_arn
      S3_BUCKET_NAME = var.s3_logging_bucket
    }
  }
}

#########################################
# DynamoDB -> Streams Processor Mapping
#########################################
resource "aws_lambda_event_source_mapping" "table_stream_mapping" {
  event_source_arn  = aws_dynamodb_table.ip_table.stream_arn
  function_name     = aws_lambda_function.ip_stream_processor.arn
  starting_position = "LATEST"
  enabled           = true
}
