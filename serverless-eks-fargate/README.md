# EKS Fargate Construct

The contruct will create
* EKS Cluster
* Fargate Profile
* Build a local Docker image, and push to ECR
* Deploy the image as application
* Creates ALB using [AWS LoadBalancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.2/deploy/configurations/)

## Deployment Diagram

![EKS Fargate CDK Construct](https://raw.githubusercontent.com/kangks/cdk-constructs/main/serverless-eks-fargate/images/EKS-Fargate%20CDK.png)
