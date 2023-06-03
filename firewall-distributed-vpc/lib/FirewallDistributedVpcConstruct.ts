import * as cdk from 'aws-cdk-lib';
import { CfnFirewall } from 'aws-cdk-lib/aws-networkfirewall';
import { Construct } from 'constructs';

export interface FirewallDistributedVpcProps {
  vpc: cdk.aws_ec2.IVpc;
  subnetList: Array<CfnFirewall.SubnetMappingProperty>;
}

export class FirewallDistributedVpc extends Construct {

  constructor(scope: Construct, id: string, props: FirewallDistributedVpcProps) {
    super(scope, id);

    let listdomains: string[] = [
      '.docker.com',
      '.aws.amazon.com',
      '.amazonaws.com',
      'downloads.nessus.org',
      'plugins.nessus.org',
      '.fedoraproject.org',
      '.duosecurity.com',
      'crl3.digicert.com',
      'crl.godaddy.com',
      'certificate.godaddy.com',
      'ocsp.godaddy.com',
      'crl4.digicert.com',
      '.digicert.com',
      '.rootca1.amazontrust.com',
      '.rootg2.amazontrust.com',
      '.amazontrust.com',
      '.sca1a.amazontrust.com',
      '.sca1b.amazontrust.com',
    ];
    const domainallowlist = new cdk.aws_networkfirewall.CfnRuleGroup(this, 'domain-allowlist', {
      capacity: 1000,
      ruleGroupName: 'domain-allowlist',
      type: 'STATEFUL',
      ruleGroup: {
        rulesSource: {
          rulesSourceList: {
            generatedRulesType: 'ALLOWLIST',
            targets: listdomains,
            targetTypes: ['TLS_SNI', 'HTTP_HOST'],
          },
        },
      },
    });    

    const allowedports = new cdk.aws_networkfirewall.CfnRuleGroup(this, 'allowed-ports', {
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
                    destinationPorts: [
                      {
                        fromPort: 80,
                        toPort: 80,
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


    const fw_policy = new cdk.aws_networkfirewall.CfnFirewallPolicy(this, 'fw_policy', {
      firewallPolicyName: 'network-firewall-policy',
      firewallPolicy: {
        statelessDefaultActions: ['aws:drop'],
        statelessFragmentDefaultActions: ['aws:drop'],
        statelessRuleGroupReferences: [{
          priority: 100,
          resourceArn: allowedports.ref,
        }],
        statefulRuleGroupReferences: [{
          resourceArn: domainallowlist.ref,
        }],
      },
    });    

    const subnetList = [];

    const firewall = new cdk.aws_networkfirewall.CfnFirewall(this, 'network-firewall', {
      firewallName: 'network-firewall',
      firewallPolicyArn: fw_policy.attrFirewallPolicyArn,
      subnetMappings: props.subnetList,
      vpcId: props.vpc.vpcId,
      deleteProtection: false,
      description: 'AWS Network Firewall to centrally control egress traffic',
      firewallPolicyChangeProtection: false,
      subnetChangeProtection: true,
    });

  }
}
