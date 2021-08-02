import { expect as expectCDK, countResources, haveResource, haveResourceLike, arrayWith, stringLike, anything, objectLike } from '@aws-cdk/assert';
import * as cdk from '@aws-cdk/core';
import * as ServerlessEksFargate from '../lib/index';
import * as path from 'path';

test('EKS Cluster Created', () => {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, "TestStack");
  // WHEN
  new ServerlessEksFargate.ServerlessEksFargate(stack, 'MyTestConstruct', {
    clusterName: "eksCluster",
    appPort: 8080,
    appLocalFolder: path.resolve(__dirname, "./testBin"),
    appDockerFilename: "dummy.Dockerfile",
    appName: "testApp"
  });
  // THEN
  expectCDK(stack).to(countResources("Custom::AWSCDK-EKS-Cluster",1));
});

test('EKS Fargate Created', () => {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, "TestStack");
  // WHEN
  new ServerlessEksFargate.ServerlessEksFargate(stack, 'MyTestConstruct', {
    clusterName: "eksCluster",
    appPort: 8080,
    appLocalFolder: path.resolve(__dirname, "./testBin"),
    appDockerFilename: "dummy.Dockerfile",
    appName: "testApp"
  });
  // THEN
  expectCDK(stack).to(countResources("Custom::AWSCDK-EKS-FargateProfile",1));  
  // expectCDK(stack).to(countResources("Custom::test",1));  
});

test('EKS Ingress Created', () => {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, "TestStack");
  const appName = "testApp"
  // WHEN
  new ServerlessEksFargate.ServerlessEksFargate(stack, 'MyTestConstruct', {
    clusterName: "eksCluster",
    appPort: 8080,
    appLocalFolder: path.resolve(__dirname, "./testBin"),
    appDockerFilename: "dummy.Dockerfile",
    appName: appName
  });
  // THEN
  expectCDK(stack).to(haveResource("Custom::AWSCDK-EKS-KubernetesObjectValue",{
    "ObjectName": stringLike(appName.toLowerCase() + "*")
  }));
});
