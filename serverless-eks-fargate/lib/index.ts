import * as cdk from '@aws-cdk/core';
import * as iam from '@aws-cdk/aws-iam';
import * as eks from '@aws-cdk/aws-eks';
import * as ec2 from '@aws-cdk/aws-ec2';
import * as cdk8s from 'cdk8s';
import * as ecrAssets from "@aws-cdk/aws-ecr-assets";
import { AwsLoadBalancerController } from './aws-loadbalancer-controller';
import { AwsObservabilityConfigmap } from './observability';
import { EXPORTNAME_EKSCLUSTER_CLUSTERARN, EXPORTNAME_EKSCLUSTER_CLUSTERNAME, EXPORTNAME_EKSCLUSTER_MASTERROLEARN, EXPORTNAME_EKSCLUSTER_VPCID, EXPORTNAME_APP_INGRESSADDRESS } from "./constants";

export interface ServerlessEksFargateProps {
  readonly clusterName?: string;
  readonly appPort: number;
  readonly appLocalFolder: string;
  readonly appDockerFilename: string;
  readonly appName: string;
}

export class ServerlessEksFargate extends cdk.Construct {

  private createEksCluster(props: ServerlessEksFargateProps):eks.Cluster{
    const masterRole = new iam.Role(this, 'cluster-master-role', {
        assumedBy: new iam.AccountRootPrincipal()
    });

    const vpc = new ec2.Vpc(this, "vpc", {
        maxAzs: 3
    });

    const fargateProfileRole = new iam.Role(this, "fargate-profile-role", {
      assumedBy: new iam.ServicePrincipal("eks-fargate-pods.amazonaws.com"),
      managedPolicies: [
          iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonEKSFargatePodExecutionRolePolicy")
      ],
      inlinePolicies: {
        "cloudWatchPolicy": new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                  "logs:CreateLogStream",
                  "logs:CreateLogGroup",
                  "logs:DescribeLogStreams",
                  "logs:PutLogEvents"
              ],
              resources: ["*"]
            })
          ]
        })
      }
    })

    const cluster = new eks.FargateCluster(this, "fargate-cluster", {
      clusterName: props.clusterName,
      vpc: vpc,
      version: eks.KubernetesVersion.V1_20,
      mastersRole: masterRole,
      coreDnsComputeType: eks.CoreDnsComputeType.FARGATE,
      endpointAccess: eks.EndpointAccess.PUBLIC,
      // override the default fargate profile created by fargate cluster
      defaultProfile: {
        selectors: [
          { namespace: "default" },
          { namespace: "kube-system" }
        ],
        podExecutionRole: fargateProfileRole
      }
    });

    const observabilityConfig = new AwsObservabilityConfigmap(new cdk8s.App(), "observability-configmap", { region: cluster.env.region });

    cluster.addCdk8sChart(`aws-observability-configmap`, observabilityConfig);

    // Deploy AWS LoadBalancer Controller onto EKS.
    new AwsLoadBalancerController(this, 'aws-loadbalancer-controller', {
        eksCluster: cluster,
        namespace: 'kube-system'
    });

    // Exported values for post-creation cluster reference
    // Needed at least 2 attributes to reuse existing EKS cluster
    //  as per https://docs.aws.amazon.com/cdk/api/latest/docs/aws-eks-readme.html#using-existing-clusters
    new cdk.CfnOutput(this, EXPORTNAME_EKSCLUSTER_CLUSTERNAME, {value: cluster.clusterName, exportName: EXPORTNAME_EKSCLUSTER_CLUSTERNAME});
    new cdk.CfnOutput(this, EXPORTNAME_EKSCLUSTER_CLUSTERARN, {value: cluster.clusterArn, exportName: EXPORTNAME_EKSCLUSTER_CLUSTERARN});
    new cdk.CfnOutput(this, EXPORTNAME_EKSCLUSTER_VPCID, {value: cluster.vpc.vpcId, exportName: EXPORTNAME_EKSCLUSTER_VPCID});
    new cdk.CfnOutput(this, EXPORTNAME_EKSCLUSTER_MASTERROLEARN, {value: cluster.kubectlRole?.roleArn || "", exportName: EXPORTNAME_EKSCLUSTER_MASTERROLEARN});

    return cluster;
  }

  private async constructFactory(eksCluster: eks.Cluster, props: ServerlessEksFargateProps){
      const appName = cdk8s.Names.toDnsLabel(props.appName);
      const appNameLabel = cdk8s.Names.toLabelValue(props.appName);

      const serviceName = `${appName}`;

      const repo = new ecrAssets.DockerImageAsset(this, `${appNameLabel}-ecr`, {
          repositoryName: appNameLabel,
          directory: props.appLocalFolder,
          file: props.appDockerFilename
      });

      const deployment = {
          apiVersion: "apps/v1",
          kind: "Deployment",
          metadata: { 
              name: `${appName}-deployment`
          },
          spec: {
              replicas: 1,
              selector: { 
                  matchLabels: {
                  "app.kubernetes.io/name": appNameLabel 
                  }
              },
              template: {
              metadata: { 
                  labels: {
                      "app.kubernetes.io/name": appNameLabel
                  }
              },
              spec: {
                  containers: [
                  {
                      name: appName,
                      image: repo.imageUri,
                      ports: [ { containerPort: props.appPort } ]
                  }
                  ]
              }
              }
          }
          };

      const service = {
          apiVersion: "v1",
          kind: "Service",
          metadata: { 
              name: serviceName
          },
          spec: {
              type: "LoadBalancer",
              ports: [ { port: 80, targetPort: props.appPort } ],
              selector: {
                  "app.kubernetes.io/name": appNameLabel
              }
          }
      };

      // https://kubernetes.io/docs/concepts/services-networking/ingress/#the-ingress-resource
      const ingress = {
          apiVersion: "networking.k8s.io/v1",
          kind: "Ingress",
          metadata: { 
              name: `${appName}-ingress`,
              annotations: {
                  "kubernetes.io/ingress.class": "alb",
                  "alb.ingress.kubernetes.io/scheme": "internet-facing",                        
                  "alb.ingress.kubernetes.io/group.name": "app-ingress",
                  "alb.ingress.kubernetes.io/target-type": "ip"
              }
          },
          spec: {
              rules: [
                  {
                      "http": {
                          paths: [
                              {
                                  path: "/",
                                  pathType: "Prefix",
                                  backend: {
                                      service: {
                                          name: serviceName,
                                          port: {
                                              number: 80
                                          }    
                                      }
                                  }
                              }
                          ]
                      }    
                  }
              ]
          }
      };

      new eks.KubernetesManifest(this, `${appNameLabel}-kub`, {
          cluster: eksCluster,
          manifest: [ deployment, service, ingress ]
      });  

      // query the ingress address
      const myServiceAddress = new eks.KubernetesObjectValue(this, 'LoadBalancerAttribute', {
          cluster: eksCluster,
          objectType: 'ingress',
          objectName: `${appName}-ingress`,
          jsonPath: '.status.loadBalancer.ingress[0].hostname',
      });

      new cdk.CfnOutput(this, EXPORTNAME_APP_INGRESSADDRESS, {value: myServiceAddress.value, exportName: EXPORTNAME_APP_INGRESSADDRESS});
  }

  constructor(scope: cdk.Construct, id: string, props: ServerlessEksFargateProps) {
    super(scope, id);

    const eksCluster = this.createEksCluster(props);
    this.constructFactory(eksCluster, props);
  }
}
