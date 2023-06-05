import * as cdk from 'aws-cdk-lib';
import { CfnFirewall, CfnRuleGroup } from 'aws-cdk-lib/aws-networkfirewall';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';

export interface NetworkFirewallDistributedConstructProps {
  vpc: cdk.aws_ec2.IVpc;
  subnetList: Array<cdk.aws_ec2.ISubnet>;
  rulesFile?: Array<fs.PathOrFileDescriptor>;
}

export class NetworkFirewallDistributedConstruct extends Construct {

  private vpc: cdk.aws_ec2.IVpc;

  constructor(scope: Construct, id: string, props: NetworkFirewallDistributedConstructProps) {
    super(scope, id);

    this.vpc = props.vpc;

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

    const statefulRuleGroups:Array<cdk.aws_networkfirewall.CfnFirewallPolicy.StatefulRuleGroupReferenceProperty> = [];

    statefulRuleGroups.push({    
      resourceArn:
        new cdk.aws_networkfirewall.CfnRuleGroup(this, 'domain-allowlist', {
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
        }).ref
      }
    );

    const rulesVariable: CfnRuleGroup.RuleVariablesProperty = {
      ipSets: {
        HOME_NET: {
          definition: [this.getHomeNet()],
        },
        EXTERNAL_NET: {
          definition: ['0.0.0.0/0'],
        }
      },      
    }

    if(props.rulesFile){
      const rulesFromFile:Array<CfnRuleGroup> = this.getRulesSourcePropertyFromFile(props.rulesFile, rulesVariable);
      for(let index=0; index<rulesFromFile.length; index++){
        statefulRuleGroups.push({    
          resourceArn:       
            rulesFromFile[index].ref
          }
        )
      }    
    };

    const rulesFromFileGroupReference = new cdk.aws_networkfirewall.CfnRuleGroup(this, 'rulesFromFile', {
      capacity: 1000,
      ruleGroupName: 'rulesFromFile',
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

    const fw_policy = new cdk.aws_networkfirewall.CfnFirewallPolicy(this, 'fw_policy', {
      firewallPolicyName: 'network-firewall-policy',
      firewallPolicy: {
        statelessDefaultActions: ['aws:drop'],
        statelessFragmentDefaultActions: ['aws:drop'],
        statelessRuleGroupReferences: [{
          priority: 100,
          resourceArn: allowedports.ref,
        }],
        statefulRuleGroupReferences: statefulRuleGroups
      },
    }); 
    
    const subnetList:Array<CfnFirewall.SubnetMappingProperty> = [];
    props.subnetList.forEach(
      (subnet)=>{
        subnetList.push({subnetId: subnet.subnetId})
      }
    )

    const firewall = new cdk.aws_networkfirewall.CfnFirewall(this, 'network-firewall', {
      firewallName: 'network-firewall',
      firewallPolicyArn: fw_policy.attrFirewallPolicyArn,
      subnetMappings: subnetList,
      vpcId: props.vpc.vpcId,
      deleteProtection: false,
      description: 'AWS Network Firewall to centrally control egress traffic',
      firewallPolicyChangeProtection: false,
      subnetChangeProtection: true,
    });

  }

  getHomeNet(): string{
    const homeNet = this.vpc.vpcCidrBlock;
    console.log("homeNet", homeNet);
    return homeNet;
  }

  getRulesSourcePropertyFromFile(filenameList:Array<fs.PathOrFileDescriptor>, rulesVariable:CfnRuleGroup.RuleVariablesProperty):Array<CfnRuleGroup>{

    const rulesSource:Array<CfnRuleGroup> = [];

    filenameList.forEach(
      (filename)=>{
        const contents = fs.readFileSync(filename, { encoding: 'utf8', flag: 'r' });
        rulesSource.push( 
          new cdk.aws_networkfirewall.CfnRuleGroup(this, path.parse(filename.toString()).name,
          {
            capacity: 1000,
            ruleGroupName: path.parse(filename.toString()).name,
            type: 'STATEFUL',
            ruleGroup: {
              ruleVariables: rulesVariable,
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

}
