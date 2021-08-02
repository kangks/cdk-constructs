import * as constructs from 'constructs';
import * as cdk8s from 'cdk8s';
import * as kplus from 'cdk8s-plus';
import { NamespaceChart } from './namespace';

export interface AwsObservabilityConfigmapProps {
  region: string
}

export class AwsObservabilityConfigmap extends cdk8s.Chart {
  constructor(scope: constructs.Construct, id: string, props: AwsObservabilityConfigmapProps) {
    super(scope, id);

    new NamespaceChart(this, "aws-observability", {name: "aws-observability"});
    
    new kplus.ConfigMap(this, 'observability',{
      "metadata": {
        "name": "aws-logging",
        "namespace": "aws-observability"
      },
      "data":{
        "output.conf": `[OUTPUT]
      Name cloudwatch_logs
      Match   *
      region ${props.region}
      log_group_name fluent-bit-cloudwatch
      log_stream_prefix from-fluent-bit-
      auto_create_group true`
      }
    });
    
  }
}