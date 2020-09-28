provider "aws" {
}

module "dcos" {
	source							= "dcos-terraform/dcos/aws"
	version							= "0.2.3"

	cluster_name					= "<cluster-name>"
	ssh_public_key_file				= "/project/aws_dcos_cluster_key.pub"
	admin_ips						= ["${data.http.whatismyip.body}/32"]

	num_masters						= "1"
	num_private_agents				= "2"
	num_public_agents				= "1"

	dcos_version					= "1.13.1"

	num_masters						= "1"
	num_private_agents				= "2"
	num_public_agents				= "1"

	dcos_version					= "1.12.3"

	dcos_instance_os				= "centos_7.5"
	bootstrap_instance_type			= "t2.medium"
	masters_instance_type			= "t2.medium"
	private_agents_instance_type	= "t2.medium"
	public_agents_instance_type		= "t2.small"

	providers = {
		aws							= "aws"
	}

	dcos_variant					= "open"

	#dcos_install_mode				= "${var.dcos_install_mode}"
	
	dcos_rexray_config = <<EOF
# YAML
rexray_config:
  rexray:
    loglevel: info
    service: ebs
  modules:
    default-admin:
      host: tcp://127.0.0.1:61003
  libstorage:
    integration:
      volume:
        operations:
          unmount:
            ignoreusedcount: true
    server:
      tasks:
        logTimeout: 5m
EOF
	
}

# Used to determine your public IP for forwarding rules
data "http" "whatismyip" {
	url								= "http://whatismyip.akamai.com/"
}

output "masters-ips" {
	value							= "${module.dcos.masters-ips}"
}

output "cluster-address" {
	value							= "${module.dcos.masters-loadbalancer}"
}

output "public-agents-loadbalancer" {
	value							= "${module.dcos.public-agents-loadbalancer}"
}

output "bootstrap-instance" {
	value							= "${module.dcos.infrastructure.bootstrap.instance}"
}

output "public-agents-ips" {
	value							= "${module.dcos.infrastructure.public_agents.public_ips}"
}

output "private-agents-ips" {
	value							= "${module.dcos.infrastructure.private_agents.public_ips}"
}


