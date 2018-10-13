#!/bin/bash

function useVirtualEnv() {
    source .env/bin/activate
}

function doExitCheck() {
    if [ "$?" -ne 0 ]; then
        exit 1
    fi
}

function v_aws() {
    ## shebangs in virtualenv too long; invoke python directly
    .env/bin/python3.6 .env/bin/aws $@
}

function v_pip() {
    ## shebangs in virtualenv too long; invoke python directly
    .env/bin/python3.6 .env/bin/pip $@
}



if [ "$1" == "setup" ]; then
    python3.6 -m venv .env
    useVirtualEnv

    v_pip install --upgrade pip
    v_pip install awscli


elif [ "$1" == "build" ]; then
    pushd docker
    sudo docker build -t ${CHECK_NAME} .
    popd


elif [ "$1" == "test" ]; then
    useVirtualEnv

    # Ideally, we would run a test framework against our image.
    # For this example, we're using a Volkswagen-type approach ;-)
    v_aws sts get-caller-identity

    echo "Tests passed!"


elif [ "$1" == "publish" ]; then
    useVirtualEnv

    v_aws ecr describe-repositories --repository-names ${CHECK_NAME}
    if [ "$?" -ne 0 ]; then
        echo "Creating repository: ${CHECK_NAME}"

        # v_aws ecr create-repository --repository-name ${CHECK_NAME}

        # Create the ECR using servicecatalog

        PRODUCT_ID=$(v_aws servicecatalog search-products --query 'ProductViewSummaries[?Name==`ECR`].ProductId' --output text)
        echo "Product ID: ${PRODUCT_ID}"

        PROVISIONING_ARTIFACT_ID=$(v_aws servicecatalog describe-product --id ${PRODUCT_ID} --query 'ProvisioningArtifacts[-1].Id' --output text)
        echo "Provisioning Artifact ID: ${PROVISIONING_ARTIFACT_ID}"

        v_aws servicecatalog provision-product \
            --product-id ${PRODUCT_ID} --provisioning-artifact-id ${PROVISIONING_ARTIFACT_ID} --provisioned-product-name ${CHECK_NAME} \
            --provisioning-parameters Key=ECRRepoName,Value=${CHECK_NAME} --tags Key=doNotShutDown,Value=true
        doExitCheck

        # TODO: loop and check for ECR existence
        sleep 60
    fi

    sudo $(v_aws ecr get-login --no-include-email)
    doExitCheck

    TAG_NAME=$(v_aws ecr describe-repositories --repository-names ${CHECK_NAME} --output text --query 'repositories[0].repositoryUri')
    echo "Docker tag name: ${TAG_NAME}"
    sudo docker tag ${CHECK_NAME}:latest ${TAG_NAME}:latest

    sudo docker push ${TAG_NAME}:latest
    doExitCheck

fi

