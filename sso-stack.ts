import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventtargets from 'aws-cdk-lib/aws-events-targets';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';

export interface SSOStackProps extends cdk.StackProps {
  userPoolId: string;
  cognitoClientSecretArn: string;
  userPoolClientId: string;
  customDomainName?: string;
  certificateArn: string;
  hostedZoneId: string;
  adminDashboardUrl: string;
  customerDashboardUrl: string;
  brevoApiKey: string;
  brevoSenderEmail?: string;
  scanAppSecret: string;
}

export class SSOStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: SSOStackProps) {
    super(scope, id, props);

    // Only create the secret rotation function - everything else already exists
    const secretRotationFunction = new lambda.Function(this, 'SecretRotationFunction', {
      functionName: 'syml-secret-rotation',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
import { SecretsManagerClient, UpdateSecretCommand } from "@aws-sdk/client-secrets-manager";
import { randomBytes } from "crypto";

const secrets = new SecretsManagerClient({ region: "us-east-1" });

export const handler = async (event) => {
  const secretArns = [
    'arn:aws:secretsmanager:us-east-1:644238524155:secret:syml-lms-app-secret-Qro2za',
    'arn:aws:secretsmanager:us-east-1:644238524155:secret:syml-scan-app-secret'
  ];

  for (const secretArn of secretArns) {
    const newSecret = randomBytes(16).toString('hex');
    
    await secrets.send(new UpdateSecretCommand({
      SecretId: secretArn,
      SecretString: JSON.stringify({ appSecret: newSecret })
    }));
    
    console.log(\`Rotated secret: \${secretArn}\`);
  }
  
  return { statusCode: 200, body: 'Secrets rotated successfully' };
};
      `),
      timeout: cdk.Duration.seconds(30),
      memorySize: 128,
    });

    secretRotationFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['secretsmanager:UpdateSecret'],
      resources: [
        'arn:aws:secretsmanager:us-east-1:644238524155:secret:syml-lms-app-secret-Qro2za',
        'arn:aws:secretsmanager:us-east-1:644238524155:secret:syml-scan-app-secret*'
      ],
    }));

    // EventBridge rule: First Sunday of month at 2 AM
    const rotationRule = new events.Rule(this, 'SecretRotationRule', {
      ruleName: 'syml-secret-rotation',
      description: 'Rotate Syml app secrets first Sunday of month at 2 AM',
      schedule: events.Schedule.cron({
        minute: '0',
        hour: '2',
        month: '*',
        weekDay: '1#1', // First Sunday
        year: '*'
      }),
    });

    rotationRule.addTarget(new eventtargets.LambdaFunction(secretRotationFunction));

    // Log Group
    new logs.LogGroup(this, 'SecretRotationLogGroup', {
      logGroupName: `/aws/lambda/${secretRotationFunction.functionName}`,
      retention: logs.RetentionDays.ONE_MONTH,
    });

    // Outputs
    new cdk.CfnOutput(this, 'SecretRotationFunctionName', {
      value: secretRotationFunction.functionName,
      description: 'Secret rotation function name',
    });
  }
}