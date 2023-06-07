import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';

export interface IAwsTransferSFTPConstructProps {
  readonly vpc?: cdk.aws_ec2.IVpc;
}

export interface IAwsTransferSFTPUseerConstructProps {
  readonly sftpServer?: cdk.aws_transfer.CfnServer,
  readonly userName: string,
  readonly s3Bucket?: cdk.aws_s3.IBucket,
  readonly kmsKey?: cdk.aws_kms.IKey;
  readonly env: any,
}

export class AwsTransferSFTPConstruct extends Construct {

  readonly sftpServer: cdk.aws_transfer.CfnServer;

  constructor(scope: Construct, id: string, props: IAwsTransferSFTPConstructProps = {}) {
    super(scope, id);

    const vpc = props.vpc ?? this.createVpc(id);

    const sftpSG = new cdk.aws_ec2.SecurityGroup(this, "sftpSG", {      
      vpc: vpc,
      securityGroupName: `sftp-sg-${id}`,      
    });

    const subnets:Array<string> = [];
    const addressAllocationIds:Array<string> = [];
    let count=1;
    vpc.selectSubnets({subnetType: cdk.aws_ec2.SubnetType.PUBLIC})
      .subnetIds
      .forEach(
      (subnetId)=>{
        subnets.push(subnetId)
        // One EIP for each Subnet
        addressAllocationIds.push(new cdk.aws_ec2.CfnEIP(this, `SftpEIP${count++}`).attrAllocationId)
      }
    )

    this.sftpServer = new cdk.aws_transfer.CfnServer(this, 'sftpServer', {
      endpointDetails: {
        vpcId: vpc.vpcId,
        addressAllocationIds: addressAllocationIds,
        subnetIds: subnets,
        securityGroupIds: [ sftpSG.securityGroupId ]
      },
      endpointType: 'VPC',
      identityProviderType: 'SERVICE_MANAGED',
      protocols: ['SFTP'],
      protocolDetails: {
        setStatOption: "ENABLE_NO_OP"
      },
      securityPolicyName: 'TransferSecurityPolicy-2023-05',
      tags: [{
        key: 'connection',
        value: 'INTERNET',
      }]
    });    

  }

  private createVpc(id: string,): cdk.aws_ec2.IVpc{
    return new cdk.aws_ec2.Vpc(this, `sftp-vpc-${id}`, {
      ipAddresses: cdk.aws_ec2.IpAddresses.cidr('10.0.0.0/27'),
      maxAzs: 2,
      subnetConfiguration: [
        {
          name: 'public-subnet',
          subnetType: cdk.aws_ec2.SubnetType.PUBLIC,
          cidrMask: 28,
        }
      ],
    });    
  }
}

export class AwsTransferSFTPUserConstruct extends Construct {

  constructor(scope: Construct, id: string, props: IAwsTransferSFTPUseerConstructProps) {
    super(scope, id);

    const sftpServer = props.sftpServer ?? new AwsTransferSFTPConstruct(this, "sftpHost").sftpServer;
    const kmsKey = props.kmsKey ?? this.createKmsKey();
    const s3Bucket = props.s3Bucket ?? this.createEncryptedS3Bucket(kmsKey, `${props.env.account}-${props.env.region}-sftp-${id}`.toLowerCase());

    const sftpHomePolicy = new cdk.aws_iam.Policy(this, "sftpHomePolicy",
    {
      policyName: `sftpHomePolicy-${id}`,
      document: new cdk.aws_iam.PolicyDocument({
        statements: [
          new cdk.aws_iam.PolicyStatement({
            actions:[
              "s3:ListBucket",
            ],
            resources: [
              `arn:aws:s3:::${s3Bucket.bucketName}`
            ]
          }),
          new cdk.aws_iam.PolicyStatement({
            actions:[
              "s3:PutObject",
              "s3:GetObject",
              "s3:GetObjectTagging",
              "s3:DeleteObject",              
              "s3:DeleteObjectVersion",
              "s3:GetObjectVersion",
              "s3:GetObjectVersionTagging",
              "s3:GetObjectACL",
              "s3:PutObjectACL"
            ],
            resources: [
              `arn:aws:s3:::${s3Bucket.bucketName}/*`
            ]
          }),
          new cdk.aws_iam.PolicyStatement({
            actions:[
              "kms:Decrypt",
              "kms:GenerateDataKey"
            ],
            resources: [
              kmsKey.keyArn
            ]
          }),
          
        ]
      })
    });

    const sftpUserRole = new cdk.aws_iam.Role(this, 'Role', {
      roleName: `sftpHomeRole-${id}`,
      assumedBy: new cdk.aws_iam.ServicePrincipal("transfer.amazonaws.com"),
      description: 'sftp User Role with RW to s3 bucket',
    })
    sftpUserRole.attachInlinePolicy(sftpHomePolicy);

    const homeDirectory = `/${s3Bucket.bucketName}/${props.userName}`;

    const cfnUser = new cdk.aws_transfer.CfnUser(this, 'sftpServerUser', {
      role: sftpUserRole.roleArn,
      serverId: sftpServer.attrServerId,
      userName: props.userName,
    
      // the properties below are optional
      // homeDirectory: homeDirectory,
      homeDirectoryMappings: [{
        entry: '/',
        target: homeDirectory
      }],
      homeDirectoryType: 'LOGICAL',
      // Logical 
      // policy: JSON.stringify(userSessionPolicy),
      tags: [{
        key: 'system',
        value: 'data',
      }],
    });

    
    new cdk.CfnOutput(this, "sftpUserOutput", {
      description: "AWS CLI to update SSH public key for user",
      value: `aws transfer import-ssh-public-key --server-id ${cfnUser.attrServerId} --user-name ${cfnUser.attrUserName} --ssh-public-key-body <ssh public key body>`
    })

  }

  createKmsKey(){
    return new cdk.aws_kms.Key(this, 'sftp-kms-key', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      pendingWindow: cdk.Duration.days(7),
      alias: 'alias/sftp-kms-key',
      description: 'KMS key for encrypting the objects in an S3 bucket',
      enableKeyRotation: false,
    });
  }

  createEncryptedS3Bucket(kmsKey: cdk.aws_kms.IKey, bucketName: string){
    return new cdk.aws_s3.Bucket(this, 'sftp-bucket', {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      encryption: cdk.aws_s3.BucketEncryption.KMS,
      // 👇 encrypt with our KMS key
      encryptionKey: kmsKey,
      bucketName: bucketName,
      versioned: true
    });
  }
}
