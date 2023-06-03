# AWS Firewall Construct

A simple AWS VPC Firewall with one stateless rule and one stateful rule to meet the AWS Config Network Firewall Conformance

## Stateless rule group

Allows only TCP:80 and TCP:443

## Stateful rule group

Allows only whitelisted domains:

* .docker.com
* .aws.amazon.com
* .amazonaws.com
* downloads.nessus.org
* plugins.nessus.org
* .fedoraproject.org
* .duosecurity.com
* crl3.digicert.com
* crl.godaddy.com
* certificate.godaddy.com

# Example use case

1. Create a new folder `network-firewall` in the same level as `cdk-construct` 
1. Initialize a CDK app using command `cdk new app --language=typescript`
2. In the `bin/network-firewall.ts`

```
#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { NetworkFirewallStack } from '../lib/network-firewall-stack';

const app = new cdk.App();
new NetworkFirewallStack(app, 'NetworkFirewallStack', {
  // needs the account and region for the Vpc lookup
  env: {
    region: process.env.CDK_DEFAULT_REGION,
    account: process.env.CDK_DEFAULT_ACCOUNT,
  },
});
```

3. In the `lib/network-firewall-stack.ts`
```
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as fwconstruct from '../../cdk-constructs/firewall-distributed-vpc'

export class NetworkFirewallStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    const vpc:cdk.aws_ec2.IVpc = cdk.aws_ec2.Vpc.fromLookup(this,"staging_vpc",{
      vpcId: <your VPC ID>
    })

    new fwconstruct.FirewallDistributedVpc(this,'fw',{
      vpc: vpc,
      subnetList:[
        {subnetId: <the subnet ID>}
      ]
    })
  
  }
}
```

# Validate with Config Conformance Pack

To ensure network firewall conformance, [deploy the conformance pack](https://docs.aws.amazon.com/config/latest/developerguide/conformance-pack-cli.html) using [Network Firewall Conformance Pack](https://github.com/awslabs/aws-config-rules/blob/master/aws-config-conformance-packs/Security-Best-Practices-for-Network-Firewall.yaml).

## Check the config rule conformation

1. Get the rule names
```
% aws configservice describe-config-rules --query 'ConfigRules[*].ConfigRuleName'
[
    "netfw-policy-default-action-fragment-packets-conformance-pack-ilk1uyn2w",
    "netfw-policy-default-action-full-packets-conformance-pack-ilk1uyn2w",
    "netfw-policy-rule-group-associated-conformance-pack-ilk1uyn2w",
    "netfw-stateless-rule-group-not-empty-conformance-pack-ilk1uyn2w"
]
```
2. Query the compliance details
```
aws configservice get-compliance-details-by-config-rule --config-rule-name netfw-policy-default-action-fragment-packets-conformance-pack-ilk1uyn2w --query 'EvaluationResults[*].ComplianceType' 
[
    "COMPLIANT"
]
```