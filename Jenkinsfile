#!/bin/groovy

pipeline {
    agent {
        // RPMs required: java-headless, python36, python36-libs, docker
        // Services required: docker
        // Permissions required: sudo

        label 'cscbuilder'
    }

    options {
        buildDiscarder(
            logRotator(
                numToKeepStr: '5'
            )
        )
    }

    environment {
        // Derive the container image name from the job name:
        // Job name: cirrus-scan-samplecheck/master
        // Container image: samplecheck

        CHECK_NAME = sh(returnStdout: true, script: 'TMP_NAME=${JOB_NAME%/*}; echo -n ${TMP_NAME#cirrus-scan-}')

        AWS_DEFAULT_REGION = 'us-west-2'

        // AWS Okta Jenkins plugin configuration
        // https://github.secureserver.net/Continuous-Integration/aws-okta-plugin

        AWS_OKTA_APPLICATION = 'https://godaddy.okta.com/home/amazon_aws/0oakmpp1rkb2ZuZsQ0x7/272'
        AWS_OKTA_CREDENTIALS = 'AWS_CICD'
        AWS_OKTA_ORGANIZATION = 'godaddy.okta.com'
        AWS_OKTA_ROLE_NAME = 'arn:aws:iam::878238275157:role/GD-AWS-Global-Audit-Dev-Private-Deploy'
    }

    stages {
        stage('Setup') {
            steps {
                sh './scripts/run.sh setup'
            }
        }

        stage('Build') {
            steps {
                sh './scripts/run.sh build'
            }
        }

        stage('Test') {
            steps {
                withAwsOkta(
                    awsApp: "${AWS_OKTA_APPLICATION}",
                    credentialsId: "${AWS_OKTA_CREDENTIALS}",
                    oktaOrganization: "${AWS_OKTA_ORGANIZATION}",
                    roleName: "${AWS_OKTA_ROLE_NAME}"
                ) {
                    sh './scripts/run.sh test'
                }
            }
        }

        stage('Publish') {
            when {
                branch 'master'
            }

            steps {
                withAwsOkta(
                    awsApp: "${AWS_OKTA_APPLICATION}",
                    credentialsId: "${AWS_OKTA_CREDENTIALS}",
                    oktaOrganization: "${AWS_OKTA_ORGANIZATION}",
                    roleName: "${AWS_OKTA_ROLE_NAME}"
                ) {
                    sh './scripts/run.sh publish'
                }
            }
        }
    }
}
