FROM bitnami/minideb:buster
RUN apt-get update && apt-get --yes upgrade && install_packages apt-utils patch uuid-runtime python3-pip
RUN python3 -m pip install --upgrade pip && python3 -m pip install setuptools wheel
RUN python3 -m pip install 'awscli>=1.18.147' 'boto3>=1.15.6'
COPY common/securityhub.py /common

# Install masscan
RUN install_packages masscan

# Provide local scripts
COPY wrapper.py /
COPY run.sh /
CMD [ "/usr/bin/python3", "/wrapper.py" ]
