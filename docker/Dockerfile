FROM bitnami/minideb:buster
RUN apt-get update && apt-get --yes upgrade && install_packages apt-utils patch uuid-runtime python3-pip
RUN python3 -m pip install --upgrade pip && python3 -m pip install setuptools wheel
RUN python3 -m pip install awscli boto3
COPY common/securityhub.py /common
COPY wrapper.py /
COPY run.sh /
CMD [ "/usr/bin/python3", "/wrapper.py" ]
