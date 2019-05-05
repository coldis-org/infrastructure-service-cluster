#!/bin/sh

# Adds the AWS key.
mkdir -p ~/.ssh
cp /project/aws_dcos_cluster_key ~/.ssh/aws_dcos_cluster_key
cp /project/aws_dcos_cluster_key.pub ~/.ssh/aws_dcos_cluster_key.pub
eval `ssh-agent -s` && \
ssh-add ~/.ssh/aws_dcos_cluster_key

# Puts the AWS basic config available to the scripts.
. /project/aws_service_config_cluster.properties
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Executes the terraform script.
terraform init
terraform plan -out=create_dcos_cluster.out
terraform apply create_dcos_cluster.out
