FROM hashicorp/terraform:0.12.29

# Installs CA certificates.
RUN apk add --no-cache \
		ca-certificates

# Installs docker.
ENV DOCKER_CHANNEL stable
ENV DOCKER_VERSION 19.03.1
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
ENV GLIBC_VER=2.32-r0
RUN apk -v --update --no-cache add \
		binutils curl unzip && \
    curl -sL https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub -o /etc/apk/keys/sgerrand.rsa.pub && \
	curl -sLO https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VER}/glibc-${GLIBC_VER}.apk && \
	curl -sLO https://github.com/sgerrand/alpine-pkg-glibc/releases/download/${GLIBC_VER}/glibc-bin-${GLIBC_VER}.apk && \
	apk add \
        glibc-${GLIBC_VER}.apk \
        glibc-bin-${GLIBC_VER}.apk && \
	curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
	unzip awscliv2.zip && \
	./aws/install && \
	rm awscliv2.zip && \
	aws --version && \
	apk -v --purge del curl unzip && \
	rm /var/cache/apk/*
	
# Installs envsubst.
ENV BUILD_DEPS="gettext" \
	RUNTIME_DEPS="libintl"
RUN set -x && \
	apk --no-cache add --update $RUNTIME_DEPS && \
	apk --no-cache add --virtual build_deps $BUILD_DEPS &&  \
	cp /usr/bin/envsubst /usr/local/bin/envsubst && \
	apk del build_deps

# Creates the work dir.
RUN mkdir /project
WORKDIR /project
VOLUME /project

# Copies the dcos scripts.
RUN mkdir -p /opt/dcos-script
COPY script /opt/dcos-script
RUN ln -s /opt/dcos-script/*.sh /usr/bin && \
	for f in /usr/bin/dcos*.sh; \
	do \
		mv -- "$f" "${f%.sh}"; \
	done

# Entrypoint.
ENTRYPOINT [ "sh", "-c" ] 
CMD [ "dcos_setup" ]
