import * as cdk8s from 'cdk8s';
import * as constructs from 'constructs';

export interface NamespaceChartProps {
  readonly name: string;
}

export class NamespaceChart extends cdk8s.Chart {
  constructor(scope: constructs.Construct, id: string, props: NamespaceChartProps) {
    super(scope, id);

    new cdk8s.ApiObject(this, `${props.name}-namespace`, {
      apiVersion: "v1",
      kind: "Namespace",
      metadata: {
        name: props.name
      }
    });
  }
}