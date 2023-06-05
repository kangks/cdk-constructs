import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as FirewallDistributedVpc from '../lib/FirewallDistributedVpcConstruct';

// example test. To run these tests, uncomment this file along with the
// example resource in lib/index.ts
test('Firewall Created', () => {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, "TestStack");
  const vpc = new cdk.aws_ec2.Vpc(stack, "vpc", {
    cidr: "10.0.0.0/24"
  });
  // WHEN
  new FirewallDistributedVpc.FirewallDistributedVpc(stack, 'MyTestConstruct', {
    vpc: vpc,
    subnetList: [
        new cdk.aws_ec2.Subnet(stack, "subnet", {
            vpcId: vpc.vpcId,
            cidrBlock: "10.0.0.0/25",
            availabilityZone: vpc.availabilityZones[0]
        })
    ],
    rulesFile: ["./test/rules.txt"]
  });
  // THEN
  const template = Template.fromStack(stack);

  template.hasResourceProperties('AWS::NetworkFirewall::RuleGroup', 
  {
    RuleGroup:{
        RulesSource:{
            "RulesString": Match.anyValue(),
        }
    }
  });
});
