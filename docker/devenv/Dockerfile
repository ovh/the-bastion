FROM ubuntu:20.04
LABEL maintainer="stephane.lesimple+bastion@ovhcloud.com"

# temporarily copy code, just to be able to install packages
COPY . /tmp/bastion

# install packages including dev-required packages ('-d')
RUN ["/tmp/bastion/bin/admin/packages-check.sh", "-i", "-d"]

# install packages needed for documentation generation
RUN ["apt-get", "install", "-y", "python3-sphinx", "python3-sphinx-rtd-theme", "make"]

# get rid of the code now
RUN ["rm", "-rf", "/tmp/bastion"]

# create empty dir for volume mount
RUN ["mkdir", "/opt/bastion"]

# just sleep
ENTRYPOINT /bin/sleep 9999d
