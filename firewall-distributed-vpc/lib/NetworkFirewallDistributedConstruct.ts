import * as cdk from 'aws-cdk-lib';
import { CfnFirewall, CfnFirewallPolicy, CfnRuleGroup } from 'aws-cdk-lib/aws-networkfirewall';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';

export interface INetworkFirewallDistributedConstructProps {
  readonly vpc: cdk.aws_ec2.IVpc;
  readonly subnetList: Array<cdk.aws_ec2.ISubnet>;
}

export interface INetworkFirewall{
  addStatelessRuleGroup(rule:cdk.aws_networkfirewall.CfnRuleGroup):INetworkFirewall;
  addStatefulRule(rule:cdk.aws_networkfirewall.CfnRuleGroup):INetworkFirewall;
  addStatefulRules(rules:Array<cdk.aws_networkfirewall.CfnRuleGroup>):INetworkFirewall;
  buildFirewall():CfnFirewall;

}

export class NetworkFirewallDistributedConstruct extends Construct implements INetworkFirewall {

  private vpc: cdk.aws_ec2.IVpc;
  private subnetList:Array<CfnFirewall.SubnetMappingProperty> = [];
  private statefulRuleGroups:Array<cdk.aws_networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty> = [];
  private statelessRulesGroups:Array<cdk.aws_networkfirewall.CfnRuleGroup> = [];

  constructor(scope: Construct, id: string, props: INetworkFirewallDistributedConstructProps) {
    super(scope, id);
    this.vpc = props.vpc;

    props.subnetList.forEach(
      (subnet)=>{
        this.subnetList.push({subnetId: subnet.subnetId})
      }
    )
  }

  addStatelessRuleGroup(rule:cdk.aws_networkfirewall.CfnRuleGroup):INetworkFirewall{
    this.statelessRulesGroups.push(rule);
    return this;
  }

  addStatefulRule(rule:cdk.aws_networkfirewall.CfnRuleGroup):INetworkFirewall{
    this.statefulRuleGroups.push({ resourceArn: rule.ref });
    return this;
  }

  addStatefulRules(rules:Array<cdk.aws_networkfirewall.CfnRuleGroup>):INetworkFirewall{
    rules.forEach(
      (rule)=>{
        this.statefulRuleGroups.push({ resourceArn: rule.ref });
      }
    )
    return this;
  }

  buildFirewall(): CfnFirewall{
    const statelessRuleGroups = ():Array<CfnFirewallPolicy.StatelessRuleGroupReferenceProperty> => {
      const groups:Array<CfnFirewallPolicy.StatelessRuleGroupReferenceProperty> = [];
      this.statelessRulesGroups.forEach(
        (stateless)=>{
          groups.push({
            priority: 100,
            // ruleDefinition: stateless,
            resourceArn: stateless.ref,
          });
        }
      )
      return groups;
    };

    const fw_policy = new cdk.aws_networkfirewall.CfnFirewallPolicy(this, 'fw_policy', {
      firewallPolicyName: 'network-firewall-policy',
      firewallPolicy: {
        statelessDefaultActions: ['aws:drop'],
        statelessFragmentDefaultActions: ['aws:drop'],
        statelessRuleGroupReferences: statelessRuleGroups(),
        statefulRuleGroupReferences: this.statefulRuleGroups
      },
    }); 
    
    const firewall = new cdk.aws_networkfirewall.CfnFirewall(this, 'network-firewall', {
      firewallName: 'network-firewall',
      firewallPolicyArn: fw_policy.attrFirewallPolicyArn,
      subnetMappings: this.subnetList,
      vpcId: this.vpc.vpcId,
      deleteProtection: false,
      description: 'AWS Network Firewall to centrally control egress traffic',
      firewallPolicyChangeProtection: false,
      subnetChangeProtection: true,
    });

    return firewall;
  }
}

export class NetworkFirewallRulesBuilder{
  
  static statefulRulesSourcePropertyFromFile(scope: Construct, filenameList:Array<string>):Array<CfnRuleGroup>{

    const rulesSource:Array<CfnRuleGroup> = [];

    filenameList.forEach(
      (filename)=>{
        const contents = fs.readFileSync(filename, { encoding: 'utf8', flag: 'r' });
        rulesSource.push( 
          new cdk.aws_networkfirewall.CfnRuleGroup(scope, path.parse(filename.toString()).name,
          {
            capacity: 1000,
            ruleGroupName: path.parse(filename.toString()).name,
            type: 'STATEFUL',
            ruleGroup: {
              rulesSource: {
                rulesString: contents.split(/\r?\n/).filter((line) => line.match("^([^#])")).join("\n")
              }
            },
          })          
        )
      }
    )
    return rulesSource;
  }

  static statelessRulesAllowedPorts(scope: Construct):cdk.aws_networkfirewall.CfnRuleGroup{
    return new cdk.aws_networkfirewall.CfnRuleGroup(scope, 'allowed-ports', {
      capacity: 1000,
      ruleGroupName: 'allowed-ports',
      type: 'STATELESS',
      ruleGroup: {
        rulesSource: {
          statelessRulesAndCustomActions: {
            statelessRules: [
              {
                priority: 1,
                ruleDefinition: {
                  actions: ['aws:forward_to_sfe'],
                  matchAttributes: {
                    destinations: [{
                      addressDefinition: '0.0.0.0/0',
                    }],
                    sources: [{
                      addressDefinition: '0.0.0.0/0',
                    }],
                    protocols: [6],
                    destinationPorts: [
                      {
                        fromPort: 80,
                        toPort: 80,
                      },
                      {
                        fromPort: 443,
                        toPort: 443,
                      },
                    ],
                  },
                },
              },
              {
                priority: 2,
                ruleDefinition: {
                  actions: ['aws:forward_to_sfe'],
                  matchAttributes: {
                    destinations: [{
                      addressDefinition: '0.0.0.0/0',
                    }],
                    sources: [{
                      addressDefinition: '0.0.0.0/0',
                    }],
                    protocols: [6],
                    sourcePorts: [
                      {
                        fromPort: 80,
                        toPort: 80,
                      },
                      {
                        fromPort: 443,
                        toPort: 443,
                      },
                    ],
                  },
                },
              }
            ],
          },
        },        
      },
    });    
  }
}