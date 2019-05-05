provider "aws" {
}

module "dcos" {
	source							= "dcos-terraform/dcos/aws"
	version							= "~> 0.1"

	cluster_name					= "<cluster-name>"
	ssh_public_key_file				= "/project/aws_dcos_cluster_key.pub"
	admin_ips						= ["${data.http.whatismyip.body}/32"]

	num_masters						= "1"
	num_private_agents				= "2"
	num_public_agents				= "1"

	dcos_version					= "1.12.0"

	dcos_instance_os				= "centos_7.5"
	bootstrap_instance_type			= "t2.medium"
	masters_instance_type			= "t2.medium"
	private_agents_instance_type	= "t2.medium"
	public_agents_instance_type		= "t2.medium"

	providers = {
		aws							= "aws"
	}

	# dcos_variant					= "ee"
	# dcos_license_key_contents		= "${file("./license.txt")}"
	dcos_variant					= "open"

	dcos_install_mode				= "${var.dcos_install_mode}"
}

variable "dcos_install_mode" {
	description						= "specifies which type of command to execute. Options: install or upgrade"
	default							= "install"
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