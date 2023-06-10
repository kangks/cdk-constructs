import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as fw from '../lib/NetworkFirewallDistributedConstruct';

test('Firewall Created', () => {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, "TestStack");
  const vpc = new cdk.aws_ec2.Vpc(stack, "vpc", {
    ipAddresses: cdk.aws_ec2.IpAddresses.cidr("10.0.0.0/24")
  });
  // WHEN
  new fw.NetworkFirewallDistributedConstruct(stack, 'MyTestConstruct', {
    vpc: vpc,
    subnetList: [
        new cdk.aws_ec2.Subnet(stack, "subnet", {
            vpcId: vpc.vpcId,
            cidrBlock: "10.0.0.0/25",
            availabilityZone: vpc.availabilityZones[0]
        })
    ]
  })
  .addStatefulRules(
    fw.NetworkFirewallRulesBuilder.statefulRulesSourcePropertyFromFile(stack,["./test/rules.txt"])    
  )
  .buildFirewall();
  ;
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
