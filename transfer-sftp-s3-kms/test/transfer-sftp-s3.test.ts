import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as TransferTftpS3 from '../lib/AwsTransferSFTPConstruct';

// example test. To run these tests, uncomment this file along with the
test('sftp with kms s3', () => {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, "TestStack");
  // WHEN
  new TransferTftpS3.AwsTransferSFTPConstruct(stack, 'MyTestConstruct');
  // THEN
  const template = Template.fromStack(stack);

  template.hasResourceProperties('AWS::Transfer::Server', 
  {
    "EndpointType": "VPC"
  });
});
