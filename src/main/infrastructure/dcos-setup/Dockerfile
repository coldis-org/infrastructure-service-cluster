FROM hashicorp/terraform:0.11.13

# Installs CA certificates.
RUN apk add --no-cache \
		ca-certificates

# Installs docker.
ENV DOCKER_CHANNEL stable
ENV DOCKER_VERSION 18.09.4
RUN set -eux; \
	\
# this "case" statement is generated via "update.sh"
	apkArch="$(apk --print-arch)"; \
	case "$apkArch" in \
		x86_64) dockerArch='x86_64' ;; \
		armhf) dockerArch='armel' ;; \
		aarch64) dockerArch='aarch64' ;; \
		ppc64le) dockerArch='ppc64le' ;; \
		s390x) dockerArch='s390x' ;; \
		*) echo >&2 "error: unsupported architecture ($apkArch)"; exit 1 ;;\
	esac; \
	\
	if ! wget -O docker.tgz "https://download.docker.com/linux/static/${DOCKER_CHANNEL}/${dockerArch}/docker-${DOCKER_VERSION}.tgz"; then \
		echo >&2 "error: failed to download 'docker-${DOCKER_VERSION}' from '${DOCKER_CHANNEL}' for '${dockerArch}'"; \
		exit 1; \
	fi; \
	\
	tar --extract \
		--file docker.tgz \
		--strip-components 1 \
		--directory /usr/local/bin/ \
	; \
	rm docker.tgz; \
	\
	dockerd --version; \
	docker --version

# Installs AWS CLI.
RUN apk -v --update add \
		python \
		py-pip \
		groff \
		less \
		mailcap \
		&& \
	pip install --upgrade awscli==1.14.5 s3cmd==2.0.1 python-magic && \
	apk -v --purge del py-pip && \
	rm /var/cache/apk/*
	
# Installs envsubst.
ENV BUILD_DEPS="gettext" \
	RUNTIME_DEPS="libintl"
RUN set -x && \
	apk add --update $RUNTIME_DEPS && \
	apk add --virtual build_deps $BUILD_DEPS &&  \
	cp /usr/bin/envsubst /usr/local/bin/envsubst && \
	apk del build_deps

# Creates the work dir.
RUN mkdir /project
WORKDIR /project
VOLUME /project

# Copies the docker entrypoint.
COPY script/run.sh /usr/bin/init

# Entrypoint.
ENTRYPOINT [ "init" ]
