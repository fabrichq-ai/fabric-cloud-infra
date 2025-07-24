terraform {
  backend "s3" {
    bucket = "fabric-tfstate-prod"
    key    = "terraform.tfstate"
    region = "ap-south-1"
    dynamodb_table = "fabric-tfstate-lock"
    encrypt = true
  }
}
