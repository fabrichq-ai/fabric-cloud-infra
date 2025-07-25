aws iam create-user --user-name terraform

aws iam create-policy \
    --policy-name fabric-terraform-policy \
    --policy-document '{
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "ec2:Vpc*",
                    "ec2:Subnet*",
                    "ec2:Route*",
                    "ec2:InternetGateway*",
                    "ec2:NatGateway*",
                    "ec2:SecurityGroup*",
                    "ec2:ElasticIp*",
                    "ec2:Describe*",
                    "ec2:Tag*"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "elasticloadbalancing:*",
                    "acm:*"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "rds:*"
                ],
                "Resource": "*"
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:*"
                ],
                "Resource": [
                    "arn:aws:s3:::fabric-tfstate-prod",
                    "arn:aws:s3:::fabric-tfstate-prod/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "dynamodb:*"
                ],
                "Resource": "arn:aws:dynamodb:*:*:table/fabric-tfstate-lock"
            }
        ]
    }'

aws iam attach-user-policy \
     --user-name terraform \
     --policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/fabric-terraform-policy

# Get the access key details
ACCESS_KEY=$(aws iam create-access-key --user-name terraform --query 'AccessKey.AccessKeyId' --output text)
SECRET_KEY=$(aws iam create-access-key --user-name terraform --query 'AccessKey.SecretAccessKey' --output text)

# Configure AWS credentials for the terraform profile
aws configure set aws_access_key_id $ACCESS_KEY --profile terraform
aws configure set aws_secret_access_key $SECRET_KEY --profile terraform
aws configure set region ap-south-1 --profile terraform

# Create backend.tf file with proper configuration
cat > backend.tf << EOF
terraform {
  backend "s3" {
    bucket = "fabric-tfstate-prod"
    key    = "terraform.tfstate"
    region = "ap-south-1"
    dynamodb_table = "fabric-tfstate-lock"
    encrypt = true
  }
}
EOF

# Create S3 bucket
aws s3api create-bucket \
  --bucket fabric-tfstate-prod \
  --region ap-south-1 \
  --create-bucket-configuration LocationConstraint=ap-south-1

# Enable versioning and encryption
aws s3api put-bucket-versioning \
  --bucket fabric-tfstate-prod \
  --versioning-configuration Status=Enabled

aws s3api put-bucket-encryption \
  --bucket fabric-tfstate-prod \
  --server-side-encryption-configuration '{
        "Rules": [{
          "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm":"AES256"}
        }]
      }'

# Create DynamoDB lock table
aws dynamodb create-table \
  --table-name fabric-tfstate-lock \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

# Output credentials for reference
echo "Terraform setup complete!"
echo "AWS Profile: terraform"
echo "Region: ap-south-1"
echo "S3 Bucket: fabric-tfstate-prod"
echo "DynamoDB Table: fabric-tfstate-lock"
echo "You can now run:"
echo "terraform init"
echo "terraform plan"
echo "terraform apply"
echo "terraform destroy"
