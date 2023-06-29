yum install -y nvme-cli
cat <<EOF >> /etc/udev/rules.d/999-aws-ebs-nvme.rules
# /etc/udev/rules.d/999-aws-ebs-nvme.rules
# ebs nvme devices
KERNEL=="nvme[0-9]*n[0-9]*", ENV{DEVTYPE}=="disk", ATTRS{model}=="Amazon Elastic Block Store", PROGRAM="/usr/local/bin/ebs-nvme-mapping /dev/%k", SYMLINK+="%c"
EOF
cat <<EOF >> /usr/local/bin/ebs-nvme-mapping
#!/bin/bash
# /usr/local/bin/ebs-nvme-mapping
vol=$(/usr/sbin/nvme id-ctrl --raw-binary "$1" | cut -c3073-3104 | tr -s " " | sed "s/ $//g")
vol=${vol#/dev/}
if [[ -n "$vol" ]]; then
	echo ${vol/xvd/sd} ${vol/sd/xvd}
fi
EOF		
chmod u+x /usr/local/bin/ebs-nvme-mapping
udevadm control --reload-rules && udevadm trigger
