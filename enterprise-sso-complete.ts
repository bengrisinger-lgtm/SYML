import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as certificatemanager from 'aws-cdk-lib/aws-certificatemanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as events from 'aws-cdk-lib/aws-events';
import * as eventtargets from 'aws-cdk-lib/aws-events-targets';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Construct } from 'constructs';

export interface EnterpriseSSOProps extends cdk.StackProps {
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

export class EnterpriseSSOStack extends cdk.Stack {
  // Core Infrastructure
  public readonly api: apigateway.IRestApi;
  public readonly domainName: apigateway.IDomainName;
  public readonly hostedZone: route53.IHostedZone;
  public readonly certificate: certificatemanager.ICertificate;

  // DynamoDB Tables (16 total)
  public readonly verificationTokensTable: dynamodb.ITable;
  public readonly auditLogTable: dynamodb.ITable;
  public readonly mfaSessionsTable: dynamodb.ITable;
  public readonly crmLoansTable: dynamodb.ITable;
  public readonly crmContactsTable: dynamodb.ITable;
  public readonly crmNotesTable: dynamodb.ITable;
  public readonly scanResultsTable: dynamodb.ITable;
  public readonly borrowersTable: dynamodb.ITable;
  public readonly loanParticipantsTable: dynamodb.ITable;
  public readonly realtorsTable: dynamodb.ITable;
  public readonly teamMembersTable: dynamodb.ITable;
  public readonly referralPartnersTable: dynamodb.ITable;
  public readonly loanDocumentsTable: dynamodb.ITable;
  public readonly loanRealtorsTable: dynamodb.ITable;
  public readonly commissionSplitsTable: dynamodb.ITable;
  public readonly userSettingsTable: dynamodb.ITable;

  // Lambda Functions (8 total)
  public readonly signupFunction: lambda.IFunction;
  public readonly verifyFunction: lambda.IFunction;
  public readonly customerDashboardFunction: lambda.IFunction;
  public readonly qrGeneratorFunction: lambda.IFunction;
  public readonly ssoServiceFunction: lambda.IFunction;
  public readonly crmWebhookFunction: lambda.IFunction;
  public readonly scanSessionGeneratorFunction: lambda.IFunction;
  public readonly secureCrmFunction: lambda.IFunction;

  // Log Groups (11 total)
  public readonly apiGatewayLogGroup: logs.ILogGroup;
  public readonly signupLogGroup: logs.ILogGroup;
  public readonly verifyLogGroup: logs.ILogGroup;
  public readonly customerDashboardLogGroup: logs.ILogGroup;
  public readonly qrGeneratorLogGroup: logs.ILogGroup;
  public readonly ssoServiceLogGroup: logs.ILogGroup;
  public readonly crmWebhookLogGroup: logs.ILogGroup;
  public readonly scanSessionGeneratorLogGroup: logs.ILogGroup;
  public readonly secureCrmLogGroup: logs.ILogGroup;
  public readonly dashboardRouterLogGroup: logs.ILogGroup;
  public readonly mfaSetupLogGroup: logs.ILogGroup;
  public readonly sessionValidationLogGroup: logs.ILogGroup;
  public readonly symlLoginLogGroup: logs.ILogGroup;

  // IAM Roles (6 total)
  public readonly signupFunctionRole: iam.IRole;
  public readonly verifyFunctionRole: iam.IRole;
  public readonly customerDashboardFunctionRole: iam.IRole;
  public readonly qrGeneratorFunctionRole: iam.IRole;
  public readonly ssoServiceFunctionRole: iam.IRole;
  public readonly crmWebhookFunctionRole: iam.IRole;
  public readonly scanSessionGeneratorFunctionRole: iam.IRole;
  public readonly secureCrmFunctionRole: iam.IRole;

  constructor(scope: Construct, id: string, props: EnterpriseSSOProps) {
    super(scope, id, props);

    const customDomainName = props.customDomainName || 'auth.syml.ai';

    // Import existing infrastructure
    this.certificate = certificatemanager.Certificate.fromCertificateArn(
      this, 'ExistingCertificate', props.certificateArn
    );

    this.hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, 'ExistingHostedZone', {
      hostedZoneId: props.hostedZoneId,
      zoneName: 'syml.ai',
    });

    // Import existing API Gateway
    this.api = apigateway.RestApi.fromRestApiId(this, 'ExistingSymlLoginApi', 'rxnsrynb3l');

    this.domainName = apigateway.DomainName.fromDomainNameAttributes(this, 'ExistingDomainName', {
      domainName: customDomainName,
      domainNameAliasHostedZoneId: 'Z2FDTNDATAQYW2', // CloudFront hosted zone ID
      domainNameAliasTarget: 'd-rxnsrynb3l.execute-api.us-east-1.amazonaws.com',
    });

    // Import all existing DynamoDB tables
    this.verificationTokensTable = dynamodb.Table.fromTableName(this, 'ExistingVerificationTokensTable', 'syml-verification-tokens');
    this.auditLogTable = dynamodb.Table.fromTableName(this, 'ExistingAuditLogTable', 'syml-audit-log');
    this.mfaSessionsTable = dynamodb.Table.fromTableName(this, 'ExistingMfaSessionsTable', 'syml-mfa-sessions');
    this.crmLoansTable = dynamodb.Table.fromTableName(this, 'ExistingCRMLoansTable', 'syml-loans');
    this.crmContactsTable = dynamodb.Table.fromTableName(this, 'ExistingCRMContactsTable', 'syml-contacts');
    this.crmNotesTable = dynamodb.Table.fromTableName(this, 'ExistingCRMNotesTable', 'syml-notes');
    this.scanResultsTable = dynamodb.Table.fromTableName(this, 'ExistingScanResultsTable', 'syml-scan-results');
    this.borrowersTable = dynamodb.Table.fromTableName(this, 'ExistingBorrowersTable', 'syml-borrowers');
    this.loanParticipantsTable = dynamodb.Table.fromTableName(this, 'ExistingLoanParticipantsTable', 'syml-loan-participants');
    this.realtorsTable = dynamodb.Table.fromTableName(this, 'ExistingRealtorsTable', 'syml-realtors');
    this.teamMembersTable = dynamodb.Table.fromTableName(this, 'ExistingTeamMembersTable', 'syml-team-members');
    this.referralPartnersTable = dynamodb.Table.fromTableName(this, 'ExistingReferralPartnersTable', 'syml-referral-partners');
    this.loanDocumentsTable = dynamodb.Table.fromTableName(this, 'ExistingLoanDocumentsTable', 'syml-loan-documents');
    this.loanRealtorsTable = dynamodb.Table.fromTableName(this, 'ExistingLoanRealtorsTable', 'syml-loan-realtors');
    this.commissionSplitsTable = dynamodb.Table.fromTableName(this, 'ExistingCommissionSplitsTable', 'syml-commission-splits');
    this.userSettingsTable = dynamodb.Table.fromTableName(this, 'ExistingUserSettingsTable', 'syml-user-settings');

    // Import all existing Lambda functions
    this.signupFunction = lambda.Function.fromFunctionName(this, 'ExistingSignupFunction', 'syml-signup');
    this.verifyFunction = lambda.Function.fromFunctionName(this, 'ExistingVerifyFunction', 'syml-verify');
    this.customerDashboardFunction = lambda.Function.fromFunctionName(this, 'ExistingCustomerDashboardFunction', 'syml-customer-dashboard');
    this.qrGeneratorFunction = lambda.Function.fromFunctionName(this, 'ExistingQRGeneratorFunction', 'syml-qr-generator');
    this.ssoServiceFunction = lambda.Function.fromFunctionName(this, 'ExistingSSOServiceFunction', 'syml-sso-service');
    this.crmWebhookFunction = lambda.Function.fromFunctionName(this, 'ExistingCRMWebhookFunction', 'syml-crm-webhook');
    this.scanSessionGeneratorFunction = lambda.Function.fromFunctionName(this, 'ExistingScanSessionGeneratorFunction', 'syml-scan-session-generator');
    this.secureCrmFunction = lambda.Function.fromFunctionName(this, 'ExistingSecureCrmFunction', 'syml-secure-crm');

    // Import all existing Log Groups
    this.apiGatewayLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingApiGatewayLogGroup', '/aws/apigateway/syml-login-api-syml-auth-stack-v3');
    this.signupLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingSignupLogGroup', '/aws/lambda/syml-signup');
    this.verifyLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingVerifyLogGroup', '/aws/lambda/syml-verify');
    this.customerDashboardLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingCustomerDashboardLogGroup', '/aws/lambda/syml-customer-dashboard');
    this.qrGeneratorLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingQRGeneratorLogGroup', '/aws/lambda/syml-qr-generator');
    this.ssoServiceLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingSSOServiceLogGroup', '/aws/lambda/syml-sso-service');
    this.crmWebhookLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingCRMWebhookLogGroup', '/aws/lambda/syml-crm-webhook');
    this.scanSessionGeneratorLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingScanSessionGeneratorLogGroup', '/aws/lambda/syml-scan-session-generator');
    this.secureCrmLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingSecureCrmLogGroup', '/aws/lambda/syml-secure-crm');
    this.dashboardRouterLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingDashboardRouterLogGroup', '/aws/lambda/syml-dashboard-router');
    this.mfaSetupLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingMfaSetupLogGroup', '/aws/lambda/syml-mfa-setup');
    this.sessionValidationLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingSessionValidationLogGroup', '/aws/lambda/syml-session-validator');
    this.symlLoginLogGroup = logs.LogGroup.fromLogGroupName(this, 'ExistingSymlLoginLogGroup', '/aws/lambda/syml-login');

    // Import all existing IAM Roles
    this.signupFunctionRole = iam.Role.fromRoleArn(this, 'ExistingSignupFunctionRole', 'arn:aws:iam::644238524155:role/syml-auth-stack-v3-SymlSignupFunctionRole-Eg6BdSMGNed6');
    this.verifyFunctionRole = iam.Role.fromRoleArn(this, 'ExistingVerifyFunctionRole', 'arn:aws:iam::644238524155:role/syml-auth-stack-v3-SymlVerifyFunctionRole-QffutB9xDNGz');
    this.customerDashboardFunctionRole = iam.Role.fromRoleArn(this, 'ExistingCustomerDashboardFunctionRole', 'arn:aws:iam::644238524155:role/syml-auth-stack-v3-CustomerDashboardFunctionRole-nUBh8HbueFlF');
    this.qrGeneratorFunctionRole = iam.Role.fromRoleArn(this, 'ExistingQRGeneratorFunctionRole', 'arn:aws:iam::644238524155:role/syml-auth-stack-v3-QRGeneratorFunctionRole-6GuA0dUq1gyb');
    this.ssoServiceFunctionRole = iam.Role.fromRoleArn(this, 'ExistingSSOServiceFunctionRole', 'arn:aws:iam::644238524155:role/syml-auth-stack-v3-SSOServiceFunctionRole-FvzfT8VDlvlQ');
    this.crmWebhookFunctionRole = iam.Role.fromRoleArn(this, 'ExistingCRMWebhookFunctionRole', 'arn:aws:iam::644238524155:role/syml-auth-stack-v3-CRMWebhookFunctionRole-AfIFOssslQNB');
    this.scanSessionGeneratorFunctionRole = iam.Role.fromRoleArn(this, 'ExistingScanSessionGeneratorFunctionRole', 'arn:aws:iam::644238524155:role/syml-auth-stack-v3-ScanSessionGeneratorFunctionRole-DY2SirnoOj9z');
    this.secureCrmFunctionRole = iam.Role.fromRoleArn(this, 'ExistingSecureCrmFunctionRole', 'arn:aws:iam::644238524155:role/syml-auth-stack-v3-SecureCRMFunctionRole-VUsMeW6UgcOx');

    // Import existing secrets
    const lmsAppSecret = secretsmanager.Secret.fromSecretCompleteArn(
      this, 'ExistingLmsAppSecret', 
      'arn:aws:secretsmanager:us-east-1:644238524155:secret:syml-lms-app-secret-Qro2za'
    );

    // Create scan app secret if it doesn't exist
    const scanAppSecret = new secretsmanager.Secret(this, 'ScanAppSecret', {
      secretName: 'syml-scan-app-secret',
      description: 'Syml Scan application secret - rotated monthly',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({}),
        generateStringKey: 'appSecret',
        excludeCharacters: '"@/\\',
        passwordLength: 32,
      },
    });

    // NEW: Secret Rotation Lambda Function
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
    process.env.LMS_SECRET_ARN,
    process.env.SCAN_SECRET_ARN
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
      environment: {
        LMS_SECRET_ARN: lmsAppSecret.secretArn,
        SCAN_SECRET_ARN: scanAppSecret.secretArn,
      },
    });

    // Grant permissions to rotation function
    lmsAppSecret.grantWrite(secretRotationFunction);
    scanAppSecret.grantWrite(secretRotationFunction);

    // NEW: EventBridge rule for monthly secret rotation
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

    // NEW: Log Group for rotation function
    new logs.LogGroup(this, 'SecretRotationLogGroup', {
      logGroupName: `/aws/lambda/${secretRotationFunction.functionName}`,
      retention: logs.RetentionDays.ONE_MONTH,
    });

    // Stack outputs for integration
    new cdk.CfnOutput(this, 'SSOApiUrl', {
      value: `https://${customDomainName}`,
      exportName: 'SymlEnterpriseSSOUrl',
      description: 'Enterprise SSO API endpoint'
    });

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: props.userPoolId,
      exportName: 'SymlEnterpriseUserPoolId',
      description: 'Cognito User Pool ID'
    });

    new cdk.CfnOutput(this, 'SessionsTableName', {
      value: this.mfaSessionsTable.tableName,
      exportName: 'SymlEnterpriseSessionsTable',
      description: 'Sessions DynamoDB table'
    });

    new cdk.CfnOutput(this, 'SecretRotationFunctionName', {
      value: secretRotationFunction.functionName,
      description: 'Secret rotation function name'
    });

    new cdk.CfnOutput(this, 'ScanSecretArn', {
      value: scanAppSecret.secretArn,
      exportName: 'SymlScanSecretArn',
      description: 'Scan application secret ARN'
    });

    new cdk.CfnOutput(this, 'LmsSecretArn', {
      value: lmsAppSecret.secretArn,
      exportName: 'SymlLmsSecretArn',
      description: 'LMS application secret ARN'
    });
  }

  /**
   * Enterprise method to onboard new applications
   */
  public onboardApplication(appName: string, appUrl: string, allowedRoles: string[]): {
    secretArn: string;
    integrationGuide: string;
  } {
    const secret = new secretsmanager.Secret(this, `${appName}Secret`, {
      secretName: `syml-${appName.toLowerCase()}-enterprise-secret`,
      description: `Syml ${appName} application secret - Enterprise SSO`,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          appName: appName.toLowerCase(),
          appUrl,
          allowedRoles,
        }),
        generateStringKey: 'appSecret',
        excludeCharacters: '"@/\\',
        passwordLength: 32,
      },
    });

    return {
      secretArn: secret.secretArn,
      integrationGuide: `
# ${appName} Enterprise SSO Integration

## Authentication Flow
1. User authenticates via https://auth.syml.ai
2. Dashboard generates service session: GET /sso/generate-service-session?sessionId={sessionId}&service=${appName.toLowerCase()}
3. User redirected to: ${appUrl}?sessionId={serviceSessionId}
4. Your app validates session: POST https://auth.syml.ai/sso/validate-session

## Validation Payload
{
  "sessionId": "service-session-id",
  "service": "${appName.toLowerCase()}",
  "appSecret": "retrieve-from-secrets-manager"
}

## Secret ARN: ${secret.secretArn}
## Allowed Roles: [${allowedRoles.join(', ')}]
      `
    };
  }
}