# AWS Transfer SFTP host backed by KMS encrpyted S3 bucket

A CDK construct to create a Transfer Family SFTP host backed by a KMS encrypted S3 bucket, and a SFTP user

Optionally, `AwsTransferSFTPUserConstruct` can be used separately to create new SFTP user by passing in the existing SFTP server id

```
new AwsTransferSFTPUserConstruct(this, "sftpUser2", {
    sftpServer: <existing SFTP server id>,
    kmsKey: <existing kmsKey that the new SFTP user need to be granted the key access>,
    s3Bucket: <eixsting s3bucket>
})
```

# Example use case

1. Create a folder, `mkdir aws-sftp`
1. Initialize a CDK app `cdk init app --language typescript`
1. Add the dependency to `@richkang/cdk-construct-transfer-sftp-s3-kms` with command `npm i --save @richkang/cdk-construct-transfer-sftp-s3-kms`
1. In the `bin/aws-sftp.ts`, pass in the `region` and `account` as `env`:

```
#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AwsSftpStack } from '../lib/aws-sftp-stack';

const app = new cdk.App();
new AwsSftpStack(app, 'AwsSftpStack', {
  env: {
    region: process.env.CDK_DEFAULT_REGION,
    account: process.env.CDK_DEFAULT_ACCOUNT,
  },

});
```
1. In the `lib/aws-sftp-stack.ts`

```
import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as sftp from "@richkang/cdk-construct-transfer-sftp-s3-kms";

export class AwsSftpCdk2Stack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: cdk.StackProps) {
    super(scope, id, props);

    new sftp.AwsTransferSFTPUserConstruct(this, "sftpUser", {
      userName: "richard",
      env: props.env
    })
  }
}
```