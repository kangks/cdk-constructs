import * as cdk from '@aws-cdk/core';
import * as eks from '@aws-cdk/aws-eks';
import * as iam from '@aws-cdk/aws-iam';

export interface AwsLoadBalancerControllerProps {
    eksCluster: eks.ICluster;
    // default 'kube-system'
    namespace?: string;
}

export class AwsLoadBalancerController extends cdk.Construct {

    constructor(
        scope: cdk.Construct,
        id: string,
        props: AwsLoadBalancerControllerProps
    ) {
        super(scope, id);

        const cluster = props.eksCluster;
        const request = require('sync-request');
        
        // install AWS load balancer via Helm charts
        const awsControllerPolicyUrl = "https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json";
        const albNamespace = props.namespace? props.namespace : 'kube-system';
        const albServiceAccount = cluster.addServiceAccount('aws-load-balancer-controller', {
            name: 'aws-load-balancer-controller',
            namespace: albNamespace,
        });

        const policyJson = request('GET', awsControllerPolicyUrl).getBody();

        ((JSON.parse(policyJson)).Statement as []).forEach((statement, _idx, _array) => {
            albServiceAccount.addToPrincipalPolicy(iam.PolicyStatement.fromJson(statement));
        });

        albServiceAccount.addToPrincipalPolicy(
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
        )

        const awsLoadBalancerControllerChart = cluster.addHelmChart('AWSLoadBalancerController', {
            chart: 'aws-load-balancer-controller',
            repository: 'https://aws.github.io/eks-charts',
            namespace: albNamespace,
            release: 'aws-load-balancer-controller',
            version: '1.2.0', // mapping to v2.2.0
            wait: true,
            timeout: cdk.Duration.minutes(15),
            values: {
            clusterName: cluster.clusterName,
            serviceAccount: {
                create: false,
                name: albServiceAccount.serviceAccountName,
            },
            vpcId: cluster.vpc.vpcId,
            region: cluster.env.region, 
            // must disable waf features for aws-cn partition
            enableShield: false,
            enableWaf: false,
            enableWafv2: false,
            },
        });

        awsLoadBalancerControllerChart.node.addDependency(albServiceAccount);
        awsLoadBalancerControllerChart.node.addDependency(cluster.openIdConnectProvider); 
    }
}
