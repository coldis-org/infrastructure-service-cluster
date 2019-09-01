# From debian.
FROM debian:10.0

# Sets locale and UTF-8 charset.
ENV TZ=America/Sao_Paulo
ENV LANG_FILE=pt_BR.UTF-8
ENV LANG=pt_BR.utf8
ENV LANGUAGE=pt_BR:pt
RUN apt-get update -y && \
	apt-get purge -y locales && \
	apt-get install -y locales && \
	rm /usr/share/locale/locale.alias && \
	ln -s /etc/locale.alias /usr/share/locale/locale.alias && \
	localedef -i pt_BR -c -f UTF-8 -A /usr/share/locale/locale.alias ${LANG_FILE} && \
	cp /usr/share/zoneinfo/${TZ} /etc/localtime && \
	apt-get purge -y locales && \
	apt-get clean -y && \
	rm -rf /var/lib/apt/lists/*

# Installs ssh, jq and curl.
RUN apt-get update -y && \
	apt-get install -y ssh jq curl maven unzip && \
	apt-get clean -y && \
	rm -rf /var/lib/apt/lists/*
	
# Installs the operational scripts.
ENV OPS_UTILS_VERSION=0.0.16
RUN mvn dependency:get -Dartifact=org.coldis.library:script-operational:${OPS_UTILS_VERSION} && \
	mkdir -p /opt/operational-utils-script && \
	cd /opt/operational-utils-script && \
	unzip ${HOME}/.m2/repository/org/coldis/library/script-operational/${OPS_UTILS_VERSION}/script-operational-${OPS_UTILS_VERSION}.jar -d . && \
	rm -R ${HOME}/.m2 && \
	chmod -R 755 . && \
	ln -s /opt/operational-utils-script/utils/script/*.sh /usr/bin && \
	for FILE in /usr/bin/operational_utils*.sh; \
	do \
		mv -- "${FILE}" "${FILE%.sh}"; \
	done
	
# Creates the work dir.
RUN mkdir /project
WORKDIR /project
VOLUME /project

# Copies the dcos scripts.
RUN mkdir -p /opt/dcos-script
COPY script /opt/dcos-script
RUN ln -s /opt/dcos-script/*.sh /usr/bin && \
	for FILE in /usr/bin/dcos*.sh; \
	do \
		mv -- "${FILE}" "${FILE%.sh}"; \
	done
	
# Installs DCOS CLI.
ENV DCOS_VERSION=1.13
RUN dcos_install --version ${DCOS_VERSION}

# Uninstall unused applications.
RUN apt-get update -y && \
	apt-get remove -y maven unzip && \
	apt-get autoremove -y && \
	apt-get clean -y && \
	rm -rf /var/lib/apt/lists/*

# Entrypoint.
ENTRYPOINT [ "dcos_init" ]
