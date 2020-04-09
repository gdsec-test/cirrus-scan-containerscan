# Template Container

### Build container

```
sudo docker build --pull -t template .

```

### Debugging (shell)

```
sudo docker run --rm -it template /bin/bash

```

### Upload container

#### Create repository on Amazon ECR (Elastic Container Registry)

```
aws ecr create-repository --repository-name template

```

#### Delete repository on Amazon ECR (Elastic Container Registry)

```
aws ecr delete-repository --repository-name template --force

```

#### Push Commands

You will need to substitute the Amazon ID in the URLs below:

```
sudo $(aws ecr get-login --no-include-email --region us-west-2)
sudo docker tag template:latest 878238275157.dkr.ecr.us-west-2.amazonaws.com/template:latest
sudo docker push 878238275157.dkr.ecr.us-west-2.amazonaws.com/template:latest

```

### Testing

See [test_container.sh](test_container.sh)

