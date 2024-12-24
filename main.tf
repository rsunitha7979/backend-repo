provider "aws" {
  region = "ap-southeast-2"
}

# Create an IAM role for the Lambda function
resource "aws_iam_role" "lambda_role" {
  name = "lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Attach policy to Lambda role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Create the Lambda Layer
resource "aws_lambda_layer_version" "psycopg2_layer" {
  layer_name          = "psycopg-layer-suni"
  description         = "A Lambda layer for psycopg2-binary"
  compatible_runtimes = ["python3.11"]
  filename            = "psy.zip"
}

# Create a lambda function for role validation
resource "aws_lambda_function" "role_validation_lambda" {
  function_name = "role-validation-lambda"
  role          = aws_iam_role.lambda_role.arn
  handler       = "role_validation.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  filename      = "role_validation.zip"

  layers = [
    aws_lambda_layer_version.psycopg2_layer.arn
  ]
}

# Create the Lambda function for main API logic
resource "aws_lambda_function" "my_lambda" {
  function_name = "my-lambda-api-sunitha-terraform"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda1.lambda_handler"
  runtime       = "python3.11"
  timeout       = 60
  filename      = "lambda1.zip"

  layers = [
    aws_lambda_layer_version.psycopg2_layer.arn
  ]

  environment {
    variables = {
      name  = "prod"
      value = "test"
    }
  }
}

resource "aws_lambda_function_url" "fnctn_url" {
  function_name      = aws_lambda_function.my_lambda.function_name
  authorization_type = "NONE"
}

# Create the API Gateway REST API
resource "aws_api_gateway_rest_api" "my_api" {
  name        = "my-lambda-api-sunitha-terraform"
  description = "API Gateway to invoke lambda"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

# Create the GET method for the root resource (/)
resource "aws_api_gateway_method" "get_method" {
  rest_api_id   = aws_api_gateway_rest_api.my_api.id
  resource_id   = aws_api_gateway_rest_api.my_api.root_resource_id
  http_method   = "GET"
  authorization = "CUSTOM" # Can be changed to other methods if needed
  authorizer_id = aws_api_gateway_authorizer.role_validation_authorizer.id
}

# Create method response for GET method
resource "aws_api_gateway_method_response" "get_method_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id
  resource_id = aws_api_gateway_rest_api.my_api.root_resource_id
  http_method = aws_api_gateway_method.get_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Headers" = true
  }
}

# Set up Lambda integration for the GET method (AWS_PROXY)
resource "aws_api_gateway_integration" "lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.my_api.id
  resource_id             = aws_api_gateway_rest_api.my_api.root_resource_id
  http_method             = aws_api_gateway_method.get_method.http_method
  type                    = "AWS_PROXY"
  integration_http_method = "POST"      # Always POST for Lambda Proxy Integration
  uri                     = aws_lambda_function.my_lambda.invoke_arn
  depends_on              = [aws_lambda_function.my_lambda]
}

# Create the Integration response for GET method
resource "aws_api_gateway_integration_response" "get_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id
  resource_id = aws_api_gateway_rest_api.my_api.root_resource_id
  http_method = aws_api_gateway_method.get_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET, POST, OPTIONS'"
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token'"
  }

  depends_on = [aws_api_gateway_integration.lambda_integration]
}

# Create OPTIONS method for CORS (pre-flight requests)
resource "aws_api_gateway_method" "options_method" {
  rest_api_id   = aws_api_gateway_rest_api.my_api.id
  resource_id   = aws_api_gateway_rest_api.my_api.root_resource_id
  http_method   = "OPTIONS"
  authorization = "NONE"
}

# Create method response for OPTIONS method (CORS)
resource "aws_api_gateway_method_response" "options_method_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id
  resource_id = aws_api_gateway_rest_api.my_api.root_resource_id
  http_method = aws_api_gateway_method.options_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = true
    "method.response.header.Access-Control-Allow-Methods" = true
    "method.response.header.Access-Control-Allow-Headers" = true
  }
}

# Set up mock integration for OPTIONS method (CORS pre-flight)
resource "aws_api_gateway_integration" "options_method_integration" {
  rest_api_id             = aws_api_gateway_rest_api.my_api.id
  resource_id             = aws_api_gateway_rest_api.my_api.root_resource_id
  http_method             = aws_api_gateway_method.options_method.http_method
  type                    = "MOCK"
  integration_http_method = "OPTIONS"
  request_templates = {
    "application/json" = "{\"statusCode\": 200}"
  }

  depends_on = [aws_api_gateway_method.options_method]
}

# Create Integration response for OPTIONS method
resource "aws_api_gateway_integration_response" "options_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id
  resource_id = aws_api_gateway_rest_api.my_api.root_resource_id
  http_method = aws_api_gateway_method.options_method.http_method
  status_code = "200"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin"  = "'*'"
    "method.response.header.Access-Control-Allow-Methods" = "'GET, POST, OPTIONS'"
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type, X-Amz-Date, Authorization, X-Api-Key, X-Amz-Security-Token, authorizationToken'"
  }

  depends_on = [aws_api_gateway_integration.options_method_integration]
}


# Create Lambda permission to allow API Gateway to invoke the Lambda function
resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.my_lambda.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.my_api.execution_arn}/*/*"
}

# Create the API Gateway deployment
resource "aws_api_gateway_deployment" "my_api_deployment" {
  rest_api_id = aws_api_gateway_rest_api.my_api.id

  depends_on = [
    aws_api_gateway_integration.lambda_integration,
    aws_api_gateway_integration.options_method_integration
  ]
}

# Create a stage for the API Gateway
resource "aws_api_gateway_stage" "my_api_stage" {
  stage_name    = "prod"
  rest_api_id   = aws_api_gateway_rest_api.my_api.id
  deployment_id = aws_api_gateway_deployment.my_api_deployment.id
}

# Create the Lambda authorizer
resource "aws_api_gateway_authorizer" "role_validation_authorizer" {
  name                      = "RoleValidation"
  rest_api_id               = aws_api_gateway_rest_api.my_api.id
  #authorizer_type           = "TOKEN"
  authorizer_uri            = "arn:aws:apigateway:ap-southeast-2:lambda:path/2015-03-31/functions/${aws_lambda_function.role_validation_lambda.arn}/invocations"
  identity_source           = "method.request.header.authorizationToken"
  authorizer_result_ttl_in_seconds = 300
}

# Output the API URL
output "api_url" {
  value = aws_api_gateway_stage.my_api_stage.invoke_url
}
# Output the Lambda function URL
output "lambda_function_url" {
  value = aws_lambda_function_url.fnctn_url.function_url
}