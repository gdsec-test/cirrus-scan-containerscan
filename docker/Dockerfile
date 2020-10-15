FROM bitnami/minideb:buster
RUN apt-get update && apt-get --yes upgrade && install_packages apt-utils curl jq patch uuid-runtime python3-pip
RUN python3 -m pip install --upgrade pip && python3 -m pip install setuptools wheel
RUN python3 -m pip install 'awscli>=1.18.147' 'boto3>=1.15.6'
RUN python3 -m pip install requests
COPY wrapper.py /
COPY tenable_instance.py /
COPY execute.py /
COPY common/*.py /common/
CMD [ "/usr/bin/python3", "/wrapper.py" ]
