FROM bitnami/minideb:buster
RUN install_packages patch uuid-runtime python3-pip && pip3 install setuptools wheel && pip3 install awscli boto3
COPY common/securityhub.py /common
COPY wrapper.py /
COPY run.sh /
CMD [ "/usr/bin/python3", "/wrapper.py" ]
