# AWS Firewall Construct

A simple AWS VPC Firewall with one stateless rule and one stateful rule to meet the AWS Config Network Firewall Conformance. 

Stateful rules group can be further extend with Suricata rules as text file

## Example stateless rule group

Allows only TCP:80 and TCP:443 by adding `NetworkFirewallRulesBuilder.statelessRulesAllowedPorts(stack)` to the `NetworkFirewallDistributedConstruct()`

## Stateful rule group

Builds from a rule text file using `NetworkFirewallRulesBuilder.statefulRulesSourcePropertyFromFile(stack,["./test/rules.txt"])` to the `NetworkFirewallDistributedConstruct()`

# Example use case

1. Create a new folder `network-firewall` in the same level as `cdk-construct` 
1. Initialize a CDK app using command `cdk new app --language=typescript`
1. Update `cdk.json` with environment context, for example
```
{
  "app": "npx ts-node --prefer-ts-exts bin/network-firewall.ts",
[...]]
  "context": {
[...]]
    "staging":{
      "vpcId": "<staging vpc id>",
      "subnets": [
        "<staging subnet id>",
        "<staging subnet id>",
        "<staging subnet id>"
      ]                
    },
    "production":{
      "vpcId": "<production vpc id>",
      "subnets": [
        "<production subnet id>",
        "<production subnet id>",
        "<production subnet id>"
      ]                
    }
  }
}
```
2. In the `bin/network-firewall.ts`

```
#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { NetworkFirewallStack } from '../lib/network-firewall-stack';

const app = new cdk.App();

const runtimeEnv = app.node.tryGetContext('config');
const context = app.node.tryGetContext(app.node.tryGetContext('config'));

const readConfig = (context:{[name:string]:any}, key:string):any => {
  if(!context[key])
    throw new Error(`${key} not found or is empty`);

  if(typeof(context[key]) === "string" && context[key].trim().length === 0 )
    throw new Error(`${key} not found or is empty`);

  if(Array.isArray(context[key]) && context[key].length < 1)
    throw new Error(`${key} not found or is empty`);

  return context[key];
}

new NetworkFirewallStack(app, 'NetworkFirewallStack', {
  vpcId: readConfig(context,"vpcId"),
  subnets: readConfig(context,"subnets"),
  environmentName: runtimeEnv,
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

export interface NetworkFirewallStackProps extends cdk.StackProps{
  readonly environmentName: string,
  readonly vpcId: string,
  readonly subnets: string[]
}

export class NetworkFirewallStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);
    const vpc:cdk.aws_ec2.IVpc = cdk.aws_ec2.Vpc.fromLookup(this,`fw-${props.environmentName}-Vpc`,
    {
      vpcId: props.vpcId
    });

    var index=0;
    const subnetList:cdk.aws_ec2.ISubnet[] = props.subnets.map((subnet)=>cdk.aws_ec2.Subnet.fromSubnetId(this, `fw-${props.environmentName}-${index++}`, subnet));

    new fwconstruct.FirewallDistributedVpc(this,'fw',{
      vpc: vpc,
      subnetList:subnetList
    })
    .addStatelessRuleGroup(
      fwconstruct.NetworkFirewallRulesBuilder.statelessRulesAllowedPorts(this)
    )
    .addStatefulRules(
      fw.NetworkFirewallRulesBuilder.statefulRulesSourcePropertyFromFile(stack,["./lib/rules.txt"])    
    )
    .buildFirewall();
  
  }
}
```
4. Update the `package.json` with the context

```
{
  "name": "network-firewall",
  "version": "0.1.0",
  "bin": {
    "network-firewall": "bin/network-firewall.js"
  },
  "scripts": {
    [...]
    "cdk-deploy-staging": "tsc && cdk deploy -c config=staging",
    "cdk-deploy-production": "tsc && cdk deploy -c config=production"
  }
[...]
}
```
5. Deploy with `npm run cdk-deploy-staging` or `npm run cdk-deploy-production`

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