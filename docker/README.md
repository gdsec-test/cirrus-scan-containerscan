# Open Port Scan Container

This container verifies that hosts do not expose unexpected open ports.

## Configuring the Open Port Scan Scanner

This scanner optionally utilizes data in the `parameter` table to control
scans. A separate scanner instance is launched for each element in the
parameter list. Normally the parameter list should contain
exactly one element.

This element may optionally define the following keys:

* `source`: The name of the zone where port probes will originate. If the name
  is unrecognized, *no scan is performed.* The zone name `aws` (the default)
  means scanning will be performed from the ECS task instance.

* `servicenow_instance`: A designator (such as `prod` or `dev`) indicating
  the ServiceNow instance that should be recorded in findings. By default,
  no instance is recorded and CirrusScan will communicate with the default
  ServiceNow instance configured elsewhere.

* `openport_severity`: The normalized severity that will be assigned to findings
  created because an unexpected open port was detected. The default is `70`.

**FIXME** - more parameters required

Note: Normalized severities fall in the range 0-100 (where `0` is Informational
and `100` is Critical). A severity outside of this range (such as `-1`) will
suppress findings of the specified type.

## Deploying the Open Port Scan Scanner

### Build container

```bash
sudo docker build --pull -t portscan .

```

### Debugging (shell)

```bash
sudo docker run --rm -it portscan /bin/bash

```

### Upload container

#### Create repository on Amazon ECR (Elastic Container Registry)

```bash
aws ecr create-repository --repository-name portscan

```

#### Delete repository on Amazon ECR (Elastic Container Registry)

```bash
aws ecr delete-repository --repository-name portscan --force

```

#### Push Commands

You will need to substitute the Amazon ID in the URLs below:

```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
sudo $(aws ecr get-login --no-include-email --region us-west-2)
sudo docker tag portscan:latest ${AWS_ACCOUNT_ID}.dkr.ecr.us-west-2.amazonaws.com/portscan:latest
sudo docker push ${AWS_ACCOUNT_ID}.dkr.ecr.us-west-2.amazonaws.com/portscan:latest

```

### Testing

See [test_container.sh](test_container.sh)
