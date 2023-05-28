import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { aws_wafv2 as wafv2 } from 'aws-cdk-lib';
import * as path from 'path';
import { MethodOptions } from 'aws-cdk-lib/aws-apigateway';

export interface S3AssetApigwWafv2Props {
  readonly s3BucketName: string;
  readonly s3Path: string;
}

export class S3AssetApigwWafv2 extends Construct {

  readonly s3PathParts: string[];
  private paramsPattern = /[^{}]+(?=})/g;

  constructor(scope: Construct, id: string, props: S3AssetApigwWafv2Props) {
      super(scope, id);

      this.s3PathParts = props.s3Path.split(path.sep); // split by s3 path "/"

      const apiGateway = this.createAPIGateway();

      const s3Bucket: cdk.aws_s3.IBucket = cdk.aws_s3.Bucket.fromBucketName(this, "s3bucketReference", props.s3BucketName);
      const executeRole = this.createExecutionRole(s3Bucket);
      s3Bucket.grantRead(executeRole);

      const s3Integration = this.createS3Integration(props.s3BucketName, props.s3Path, executeRole);
      this.addAssetsEndpoint(apiGateway, s3Integration);

      const webACL = this.creatWafv2();
      new wafv2.CfnWebACLAssociation(this,'ApiGWWebACLAssociation', {
        resourceArn: apiGateway.deploymentStage.stageArn,
        webAclArn: webACL.attrArn,
      });    
  }

  private createAPIGateway() {
      return new cdk.aws_apigateway.RestApi(this, "assets-api", {
          defaultCorsPreflightOptions: {
              allowOrigins: cdk.aws_apigateway.Cors.ALL_ORIGINS,
          },
          deployOptions: {
              stageName: 'v1',
          },
          restApiName: "Static assets provider",
          description: "Serves assets from the S3 bucket.",
          binaryMediaTypes: ["*/*"],

          // disable HTTP compression to meet https://ihp.csa.gov.sg/home
          // minimumCompressionSize: 0, 
      });
  }

  private createExecutionRole(bucket: cdk.aws_s3.IBucket) {
      const executeRole = new cdk.aws_iam.Role(this, "api-gateway-s3-assume-role", {
          assumedBy: new cdk.aws_iam.ServicePrincipal("apigateway.amazonaws.com"),
          roleName: "API-Gateway-S3-Integration-Role",
      });

      executeRole.addToPolicy(
          new cdk.aws_iam.PolicyStatement({
              resources: [bucket.bucketArn],
              actions: ["s3:Get"],
          })
      );

      return executeRole;
  }

  private addAssetsEndpoint(
      apiGateway: cdk.aws_apigateway.RestApi,
      s3Integration: cdk.aws_apigateway.AwsIntegration
  ) {

      let requestParameters: { [key: string]: boolean } = {
          "method.request.header.Content-Type": true,
      };

      let apigwResource = apiGateway.root

      this.s3PathParts.forEach(
          (pathToken) => {
              if (pathToken.match(this.paramsPattern)) {
                  let extractParams = pathToken.match(this.paramsPattern);
                  apigwResource = apigwResource.addResource(`{${extractParams}}`);                    
                  requestParameters[`method.request.path.${extractParams}`] = true
              }
          }
      )

      let methodOptions: MethodOptions = {
          methodResponses: [
              {
                  statusCode: "200",
                  responseParameters: {
                      "method.response.header.Content-Type": true,
                      "method.response.header.Strict-Transport-Security": true,
                  },
              },
          ],
          requestParameters: requestParameters            
      }

      apigwResource.addMethod("GET", s3Integration, methodOptions);
  }

  private createS3Integration(
      s3BucketName: string, //cdk.aws_s3.IBucket, 
      s3Path: string,
      executeRole: cdk.aws_iam.Role
  ) {

      let requestParameters: { [key: string]: string } = {};

      this.s3PathParts.forEach(
          (pathToken) => {
              if (pathToken.match(this.paramsPattern)) {
                  let extractParams = pathToken.match(this.paramsPattern);
                  requestParameters[`integration.request.path.${extractParams}`] = `method.request.path.${extractParams}`
              }
          }
      )

      const s3fullPath = `${s3BucketName}/${s3Path}`;

      return new cdk.aws_apigateway.AwsIntegration({
          service: "s3",
          integrationHttpMethod: "GET",
          path: s3fullPath,
          options: {
              credentialsRole: executeRole,
              integrationResponses: [
                  {
                      statusCode: "200",
                      responseParameters: {
                          "method.response.header.Content-Type": "integration.response.header.Content-Type",
                          "method.response.header.Strict-Transport-Security": "'max-age=31536000; includeSubDomains; preload'",
                      },
                  },
              ],
              requestParameters: requestParameters
          },
      });
  }

  private creatWafv2() {
      return new wafv2.CfnWebACL(this,
          'ApiGWWebAcl',
          {
              defaultAction: {
                  allow: {}
              },
              scope: 'REGIONAL',
              visibilityConfig: {
                  cloudWatchMetricsEnabled: true,
                  metricName: 'MetricForWebACLCDK',
                  sampledRequestsEnabled: true,
              },
              name: 'ApiGWWebAcl',
              rules: [{
                  name: 'CRSRule',
                  priority: 0,
                  statement: {
                      managedRuleGroupStatement: {
                          name: 'AWSManagedRulesCommonRuleSet',
                          vendorName: 'AWS'
                      }
                  },
                  visibilityConfig: {
                      cloudWatchMetricsEnabled: true,
                      metricName: 'MetricForWebACLCDK-CRS',
                      sampledRequestsEnabled: true,
                  },
                  overrideAction: {
                      none: {}
                  },
              }]
          });
  }
}
