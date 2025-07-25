Discussion: https://chatgpt.com/c/68821a74-8b10-832e-8827-5c42c814e8d9



Running the Terraform Script:

1. Setting Up and Basic Checks:
    1. Verify Backend.
    2. Configure backend if required.
    3. Setup default variables in tfvars file.

2. Making Changes:
    1. Run plan command to verify if script is all good.
        `terraform plan -var-file dev.tfvars`
    
    2. Run apply command with acm certificate target to apply the changes.
        `terraform plan -var-file dev.tfvars -target=aws_acm_certificate.stage`
        `terraform apply -var-file dev.tfvars -target=aws_acm_certificate.stage`

        output: acm_dns_validation_records
    
    3. Go to Namecheap and add the CNAME records from the output.
    4. Wait for the ACM to certificate status change to issued.
    5. Run apply command to apply the changes.
        `terraform plan -var-file dev.tfvars`
        `terraform apply -var-file dev.tfvars`
    
    


