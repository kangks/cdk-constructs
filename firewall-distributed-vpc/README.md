# AWS Firewall Construct

A simple AWS VPC Firewall with one stateless rule and one stateful rule to meet the AWS Config Network Firewall Conformance. 

Stateful rules group can be further extend with Suricata rules as text file

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

4. Create a Suricata text file in `lib/rules.txt` as below. More examples can be found in https://suricata.readthedocs.io/en/suricata-6.0.2/rules/intro.html

```
pass ip 10.1.0.0/16 any -> 10.0.0.0/16 any (sid:100;)
drop ip any any <> any any (sid:101;)
alert tcp any any -> 1.1.1.1/32 80 (sid:102;msg:"example message";)
drop tls $HOME_NET any -> $EXTERNAL_NET any (tls.sni; content:"example.com"; startswith; nocase; endswith; msg:"matching TLS denylisted FQDNs"; priority:1; flow:to_server, established; sid:103; rev:1;)
drop http $HOME_NET any -> $EXTERNAL_NET any (http.host; content:"example.com"; startswith; endswith; msg:"matching HTTP denylisted FQDNs"; priority:1; flow:to_server, established; sid:104; rev:1;)
```

3. In the `lib/network-firewall-stack.ts`
```
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as fwconstruct from '../../cdk-constructs/firewall-distributed-vpc'

export class NetworkFirewallStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    const vpc:cdk.aws_ec2.IVpc = cdk.aws_ec2.Vpc.fromLookup(this,"fwVpc",
    {
      vpcId: <your VPC ID>
    });

    const subnet = [
      cdk.aws_ec2.Subnet.fromSubnetId(this, "subnet1", <subnet 1>),
      cdk.aws_ec2.Subnet.fromSubnetId(this, "subnet2", <subnet 2>)
    ]


    new fwconstruct.FirewallDistributedVpc(this,'fw',{
      vpc: vpc,
      subnetList: subnet,
      rulesFile: ["./lib/rules.txt"]
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