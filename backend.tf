terraform {
  backend "s3" {
    bucket = "backend-repo-statefile-bucket"
    key = "terraform.tfstate"
    dynamodb_table = "dynamo-table-state-lock"
    region = "ap-southeast-2"
    }
}

