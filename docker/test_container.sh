#!/bin/sh -x

# This script simulates the processing that will be done by the executor when
# it spawns tasks to run each container.


# The executor will pull these settings from DynamoDB:

# aws s3api create-bucket --bucket dev-private-cirrus-scan-reports --region us-west-2 --create-bucket-configuration LocationConstraint=us-west-2
# aws s3api create-bucket --bucket dev-private-cirrus-scan-results --region us-west-2 --create-bucket-configuration LocationConstraint=us-west-2

# Bucket policy to allow viewing the HTML report:
# {"Statement": [{"Effect": "Allow", "Principal": "*", "Sid": "PublicReadGetObject", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::dev-private-cirrus-scan-reports/*"}], "Version": "2012-10-17"}

CIRRUS_SCAN_REPORTS_S3HOST="s3-us-west-2.amazonaws.com"
CIRRUS_SCAN_REPORTS_BUCKET="dev-private-cirrus-scan-reports"
CIRRUS_SCAN_RESULTS_BUCKET="dev-private-cirrus-scan-results"


# Generate a unique name that will serve as the S3 parameter bucket name as
# well as the temporary file we'll create here:

PARAMETER_BUCKET="$(uuidgen)-cirrus-scan-params"


# Generate a unique name that will serve as the S3 scratch bucket:

SCRATCH_BUCKET="$(uuidgen)-cirrus-scan-test"


# Substitute ___SUBSTITUTION_STRINGS___ with real values:

cp test_parameters.json ${PARAMETER_BUCKET}.json

sed -i "s/___CIRRUS_SCAN_REPORTS_S3HOST___/${CIRRUS_SCAN_REPORTS_S3HOST}/g" ${PARAMETER_BUCKET}.json
sed -i "s/___CIRRUS_SCAN_REPORTS_BUCKET___/${CIRRUS_SCAN_REPORTS_BUCKET}/g" ${PARAMETER_BUCKET}.json
sed -i "s/___CIRRUS_SCAN_RESULTS_BUCKET___/${CIRRUS_SCAN_RESULTS_BUCKET}/g" ${PARAMETER_BUCKET}.json

sed -i "s/___SCRATCH_BUCKET___/${SCRATCH_BUCKET}/g" ${PARAMETER_BUCKET}.json


# Create the temporary S3 parameter bucket and copy the parameters to it:

aws s3api create-bucket --bucket ${PARAMETER_BUCKET} --region us-west-2 --create-bucket-configuration LocationConstraint=us-west-2
aws s3 cp ${PARAMETER_BUCKET}.json s3://${PARAMETER_BUCKET}/parameters
rm -f ${PARAMETER_BUCKET}.json


# Create the scratch S3 bucket with test input files:

aws s3api create-bucket --bucket ${SCRATCH_BUCKET} --region us-west-2 --create-bucket-configuration LocationConstraint=us-west-2
aws s3 cp input-file-1 s3://${SCRATCH_BUCKET}/input-file-1
aws s3 cp input-file-2 s3://${SCRATCH_BUCKET}/input-file-2


# Specify the S3 parameter bucket for the container, and run it:

BUCKET_ID=${PARAMETER_BUCKET}
BUCKET_KEY=parameters

sudo docker run --rm -it \
    -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
    -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
    -e AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN} \
    -e AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-west-2} \
    -e BUCKET_ID=${BUCKET_ID} \
    -e BUCKET_KEY=${BUCKET_KEY} \
    template


# Remove the temporary S3 parameter bucket:

aws s3 rm s3://${PARAMETER_BUCKET}/parameters
aws s3api delete-bucket --bucket ${PARAMETER_BUCKET}


# Remove the scratch S3 bucket:

aws s3 rm s3://${SCRATCH_BUCKET}/input-file-1
aws s3 rm s3://${SCRATCH_BUCKET}/input-file-2
aws s3api delete-bucket --bucket ${SCRATCH_BUCKET}


# Verify expected contents from keys in the result bucket:

TEST1_OUTPUT=$(aws s3 cp s3://${CIRRUS_SCAN_RESULTS_BUCKET}/output-file-1 -)
TEST2_OUTPUT=$(aws s3 cp s3://${CIRRUS_SCAN_RESULTS_BUCKET}/output-file-2 -)

echo -n "Test 1: "
if [ "${TEST1_OUTPUT}" = "7a5c9ff59690f187fc2031b013f1c637a0acb8b5da10d3800b570c595b03dc4d  /root/input1.txt" ]; then
    echo -e "PASS\n"
else
    echo -e "FAIL\n"
fi

echo -n "Test 2: "
if [ "${TEST2_OUTPUT}" = "7f28a79a1476a15785c5a5e4f0e131765a1683385bd11927c002ebd8d28afc0a  /root/input2.txt" ]; then
    echo -e "PASS\n"
else
    echo -e "FAIL\n"
fi

