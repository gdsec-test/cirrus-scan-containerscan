# Container Scan Container

This container verifies that container images in ECR registryies don't have high or critical compliance 
or vulnerability exposure.

## Configuring the ContainerScan Scanner

This container executes the Prisma Compute defender instance.  It is assumed
that the current execution role has the policies required to access the various
AWS resources.  The following AWS Managed Policies can be attached to the
principal in order to grant necessary permissions:

* ServiceCatalog:EndUserFullAccess
* AssumeRole:GD-AuditFramework-SecretsManagerReadOnlyRole
* ReadOnlyAccess
* SecurityAudit

The following AWS Managed Policies is required for Prisma defender to scan a given ECR registry:
* AmazonEC2ContainerRegistryReadOnly


## Deploying the Container Scan Scanner

### Build container

```bash
sudo docker build --pull -t containerscan .

```

### Debugging (shell)

```bash
sudo docker run --rm -it containerscan /bin/bash

```

### Upload container

#### Create repository on Amazon ECR (Elastic Container Registry)

```bash
aws ecr create-repository --repository-name containerscan

```

#### Delete repository on Amazon ECR (Elastic Container Registry)

```bash
aws ecr delete-repository --repository-name containerscan --force

```

#### Push Commands

You will need to substitute the Amazon ID in the URLs below:

```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
sudo $(aws ecr get-login --no-include-email --region us-west-2)
sudo docker tag containerscan:latest ${AWS_ACCOUNT_ID}.dkr.ecr.us-west-2.amazonaws.com/containerscan:latest
sudo docker push ${AWS_ACCOUNT_ID}.dkr.ecr.us-west-2.amazonaws.com/containerscan:latest

```
