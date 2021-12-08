#!/usr/bin/env python

import json
import boto3


def main():   
    dynamodb = boto3.resource("dynamodb")
    
    # Variable task parameters. We should not alarm on DNS or bastion
    # hosts until further notice ("1 May 2020", maybe).

    parameter = dynamodb.Table("parameter")

    parameter.put_item(
        Item={
            "task": "containerscan",
            "account": "default",
            "value": {
                "enabled": False,
                "comment": "Disable all accounts during beta testing",
            },
        }
    )

    # OX accounts #felix
    # Dev-Private: 102415972902
    # Dev: 811260440519
    # Test: 606683370182
    # Prod: 781134545670

    # security
    # dev private: 226955763576
    # prod: 811396126940
    # 471216590466	gd-aws-usa-cio-securitytesting-dev
    

    #audit
    # 672751022979	gd-aws-global-audit-prod
    # 878238275157	gd-aws-global-audit-dev-private
    # 488216410199	gd-aws-global-audit-dev

    ## ESSP @thoward
    # TestingScripts  ElasticCloud-Dev  918084454465
    # TestingScripts  ElasticCloud-Prod 736814648539
    # Production      ElasticCloud-Prod 638569024380
    # PCI             ElasticCloud-Prod 600352051928
    # Registry        ElasticCloud-Prod 606361256179
    # Hackathon       ElasticCloud-Prod 822905237458

    # PCP accounts:
	# • Dev-Private: 654363770875
	# • Dev: 626324865630
	# • Test: 644667727024
	# • Stage: 740325375987
    # Prod: 447181963750


    #golden AMI
    	# 160573626253 - GoldenAMI-Dev
	    # 042958031843 - Test
        # 764525110978 - Prod

    #dev private accounts
    parameter.put_item(Item={"task": "containerscan", "account": "102415972902", "value": {
                       "enabled": True, "comment": "dev private - OX"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "226955763576", "value": {
                       "enabled": True, "comment": "dev private - security"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "878238275157", "value": {
                       "enabled": True, "comment": "dev private - audit"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "654363770875", "value": {
                       "enabled": True, "comment": "dev private - PCP"}, })


    #dev accounts
    parameter.put_item(Item={"task": "containerscan", "account": "918084454465", "value": {
                       "enabled": True, "comment": "dev - ESSP TestingScripts"}, })

    parameter.put_item(Item={"task": "containerscan", "account": "626324865630", "value": {
                       "enabled": True, "comment": "dev - PCP"}, })

    parameter.put_item(Item={"task": "containerscan", "account": "160573626253", "value": {
                   "enabled": True, "comment": "dev - Golden AMI"}, })

    #test accounts
    parameter.put_item(Item={"task": "containerscan", "account": "606683370182", "value": {
                       "enabled": True, "comment": "test - OX"}, })

    parameter.put_item(Item={"task": "containerscan", "account": "644667727024", "value": {
                       "enabled": True, "comment": "test - PCP"}, })

    parameter.put_item(Item={"task": "containerscan", "account": "042958031843", "value": {
               "enabled": True, "comment": "test - Golden AMI"}, })

    #prod accounts
    ## CFS #gpang
    # ARIFACTS_ACCOUNT_ID_ORG_DICT = {   
    # "non-pci": "534479642073",    
    # "hackathon": "122028576130",    
    # "pci": "295403150378",    
    # "dev": "234299709304", 
    # "artifacts": "345372144177"}

    parameter.put_item(Item={"task": "containerscan", "account": "781134545670", "value": {
                       "enabled": True, "comment": "prod - OX"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "811396126940", "value": {
                       "enabled": True, "comment": "prod - security"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "672751022979", "value": {
                       "enabled": True, "comment": "prod - audit"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "447181963750", "value": {
                       "enabled": True, "comment": "prod - PCP"}, })

    parameter.put_item(Item={"task": "containerscan", "account": "534479642073", "value": {
                       "enabled": True, "comment": "prod - CFS artifacts - non-pci"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "122028576130", "value": {
                       "enabled": True, "comment": "prod - CFS artifacts - hackathon"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "295403150378", "value": {
                       "enabled": True, "comment": "prod - CFS artifacts - pci"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "234299709304", "value": {
                       "enabled": True, "comment": "prod - CFS artifacts - dev"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "345372144177", "value": {
                       "enabled": True, "comment": "prod - CFS artifacts - artifacts"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "736814648539", "value": {
                       "enabled": True, "comment": "prod - ESSP TestingScripts"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "638569024380", "value": {
                       "enabled": True, "comment": "prod - ESSP Production"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "600352051928", "value": {
                       "enabled": True, "comment": "prod - ESSP PCI"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "606361256179", "value": {
                       "enabled": True, "comment": "prod - ESSP Registry"}, })
    parameter.put_item(Item={"task": "containerscan", "account": "822905237458", "value": {
                       "enabled": True, "comment": "prod - ESSP Hackathon"}, })

    parameter.put_item(Item={"task": "containerscan", "account": "764525110978", "value": {
           "enabled": True, "comment": "prod - Golden AMI"}, })

if __name__ == "__main__":
    main()
