import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as route53 from 'aws-cdk-lib/aws-route53';
import * as targets from 'aws-cdk-lib/aws-route53-targets';
import * as certificatemanager from 'aws-cdk-lib/aws-certificatemanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface ApplicationConfig {
  name: string;
  url: string;
  allowedRoles: string[];
  description: string;
}

export class EnterpriseSSOStack extends cdk.Stack {
  public readonly userPool: cognito.IUserPool;
  public readonly api: apigateway.RestApi;
  public readonly sessionsTable: dynamodb.ITable;
  public readonly auditTable: dynamodb.ITable;
  public readonly ssoFunction: lambda.Function;
  private readonly applicationSecrets: Map<string, secretsmanager.ISecret> = new Map();

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Import existing CloudFormation resources
    this.userPool = cognito.UserPool.fromUserPoolId(this, 'ExistingUserPool', 
      cdk.Fn.importValue('SymlUserPoolId') || 'us-east-1_example'
    );

    this.sessionsTable = dynamodb.Table.fromTableName(this, 'ExistingSessionsTable', 
      'syml-mfa-sessions'
    );

    this.auditTable = dynamodb.Table.fromTableName(this, 'ExistingAuditTable', 
      'syml-audit-log'
    );

    // Enterprise SSO Lambda with comprehensive functionality
    this.ssoFunction = new lambda.Function(this, 'EnterpriseSSOFunction', {
      functionName: 'syml-enterprise-sso',
      runtime: lambda.Runtime.NODEJS_20_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset('lambda'),
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      environment: {
        USER_POOL_ID: this.userPool.userPoolId,
        SESSIONS_TABLE: this.sessionsTable.tableName,
        AUDIT_TABLE: this.auditTable.tableName,
        REGION: this.region,
      },
      tracing: lambda.Tracing.ACTIVE,
    });

    // Enterprise-grade IAM permissions
    this.ssoFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'cognito-idp:AdminInitiateAuth',
        'cognito-idp:AdminRespondToAuthChallenge',
        'cognito-idp:AssociateSoftwareToken',
        'cognito-idp:VerifySoftwareToken',
        'cognito-idp:AdminSetUserMFAPreference',
        'cognito-idp:GetUser',
        'cognito-idp:AdminGetUser',
        'cognito-idp:ListUsersInGroup'
      ],
      resources: [this.userPool.userPoolArn]
    }));

    this.ssoFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'dynamodb:GetItem',
        'dynamodb:PutItem',
        'dynamodb:UpdateItem',
        'dynamodb:DeleteItem'
      ],
      resources: [this.sessionsTable.tableArn, this.auditTable.tableArn]
    }));

    this.ssoFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['secretsmanager:GetSecretValue'],
      resources: ['arn:aws:secretsmanager:*:*:secret:syml-*']
    }));

    this.ssoFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['lambda:InvokeFunction'],
      resources: ['arn:aws:lambda:*:*:function:syml-qr-generator']
    }));

    // Enterprise API Gateway with comprehensive routing
    this.api = new apigateway.RestApi(this, 'EnterpriseSSOAPI', {
      restApiName: 'Syml Enterprise SSO',
      description: 'Enterprise-grade SSO system for all Syml applications',
      defaultCorsPreflightOptions: {
        allowOrigins: ['https://lms.syml.ai', 'https://statements.syml.ai', 'https://syml.ai', 'https://auth.syml.ai'],
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
        allowCredentials: true,
      },
      deployOptions: {
        stageName: 'prod',
        throttlingRateLimit: 2000,
        throttlingBurstLimit: 5000,
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
        dataTraceEnabled: true,
        metricsEnabled: true,
      },
    });

    const ssoIntegration = new apigateway.LambdaIntegration(this.ssoFunction, {
      requestTemplates: { 'application/json': '{ "statusCode": "200" }' },
      proxy: true,
    });

    // Core SSO endpoints
    const sso = this.api.root.addResource('sso');
    sso.addMethod('ANY', ssoIntegration);
    
    const ssoLogin = sso.addResource('login');
    ssoLogin.addMethod('POST', ssoIntegration);
    ssoLogin.addMethod('OPTIONS', ssoIntegration);
    
    const ssoValidate = sso.addResource('validate-session');
    ssoValidate.addMethod('POST', ssoIntegration);
    ssoValidate.addMethod('OPTIONS', ssoIntegration);
    
    const ssoGenerate = sso.addResource('generate-service-session');
    ssoGenerate.addMethod('GET', ssoIntegration);
    
    const ssoRefresh = sso.addResource('refresh-session');
    ssoRefresh.addMethod('POST', ssoIntegration);
    ssoRefresh.addMethod('OPTIONS', ssoIntegration);
    
    const ssoLogout = sso.addResource('logout');
    ssoLogout.addMethod('POST', ssoIntegration);
    ssoLogout.addMethod('OPTIONS', ssoIntegration);
    
    const ssoSecret = sso.addResource('get-service-secret');
    ssoSecret.addMethod('GET', ssoIntegration);

    // Application management endpoints
    const apps = sso.addResource('applications');
    apps.addMethod('GET', ssoIntegration); // List applications
    apps.addMethod('POST', ssoIntegration); // Register new application
    
    const appResource = apps.addResource('{appId}');
    appResource.addMethod('GET', ssoIntegration); // Get application details
    appResource.addMethod('PUT', ssoIntegration); // Update application
    appResource.addMethod('DELETE', ssoIntegration); // Remove application

    // Legacy compatibility endpoints (maintain existing functionality)
    const login = this.api.root.addResource('login');
    login.addMethod('GET', ssoIntegration);
    login.addMethod('POST', ssoIntegration);
    
    const mfaSetup = this.api.root.addResource('mfa-setup');
    mfaSetup.addMethod('GET', ssoIntegration);
    mfaSetup.addMethod('POST', ssoIntegration);
    
    const dashboardRouter = this.api.root.addResource('dashboard-router');
    dashboardRouter.addMethod('GET', ssoIntegration);
    
    const validateSession = this.api.root.addResource('validate-session');
    validateSession.addMethod('POST', ssoIntegration);
    validateSession.addMethod('OPTIONS', ssoIntegration);

    // Custom domain with SSL
    const certificate = certificatemanager.Certificate.fromCertificateArn(
      this,
      'SSLCertificate',
      'arn:aws:acm:us-east-1:644238524155:certificate/44bf2ce6-5a53-4979-936e-54603ff1e73e'
    );

    const domain = this.api.addDomainName('SSODomain', {
      domainName: 'sso.syml.ai',
      certificate: certificate,
    });

    // Route53 DNS record
    const hostedZone = route53.HostedZone.fromHostedZoneAttributes(this, 'HostedZone', {
      hostedZoneId: 'Z0711504107FB2IVXZFNP',
      zoneName: 'syml.ai',
    });

    new route53.ARecord(this, 'SSORecord', {
      zone: hostedZone,
      recordName: 'sso',
      target: route53.RecordTarget.fromAlias(new targets.ApiGatewayDomain(domain)),
    });

    // Pre-register core applications
    this.registerApplication({
      name: 'scan',
      url: 'https://statements.syml.ai',
      allowedRoles: ['admin', 'user'],
      description: 'Syml|Scan - Bank Statement Analysis'
    });

    this.registerApplication({
      name: 'lms',
      url: 'https://lms.syml.ai',
      allowedRoles: ['admin'],
      description: 'Syml LMS - Loan Management System'
    });

    this.registerApplication({
      name: 'crm',
      url: 'https://lms.syml.ai',
      allowedRoles: ['admin'],
      description: 'Syml CRM - Customer Relationship Management'
    });

    // Stack outputs for application integration
    new cdk.CfnOutput(this, 'SSOApiUrl', {
      value: 'https://sso.syml.ai',
      exportName: 'SymlEnterpriseSSOUrl',
      description: 'Enterprise SSO API endpoint'
    });

    new cdk.CfnOutput(this, 'UserPoolId', {
      value: this.userPool.userPoolId,
      exportName: 'SymlEnterpriseUserPoolId',
      description: 'Cognito User Pool ID'
    });

    new cdk.CfnOutput(this, 'SessionsTableName', {
      value: this.sessionsTable.tableName,
      exportName: 'SymlEnterpriseSessionsTable',
      description: 'Sessions DynamoDB table'
    });

    new cdk.CfnOutput(this, 'AuditTableName', {
      value: this.auditTable.tableName,
      exportName: 'SymlEnterpriseAuditTable',
      description: 'Audit log DynamoDB table'
    });
  }

  /**
   * Register a new application with the SSO system
   * This creates the necessary secrets and client configurations
   */
  public registerApplication(config: ApplicationConfig): void {
    // Create application-specific secret
    const secret = new secretsmanager.Secret(this, `${config.name}Secret`, {
      secretName: `syml-${config.name}-enterprise-secret`,
      description: `${config.description} - Enterprise SSO secret`,
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          appName: config.name,
          appUrl: config.url,
          allowedRoles: config.allowedRoles,
          description: config.description
        }),
        generateStringKey: 'appSecret',
        excludeCharacters: '"@/\\',
        passwordLength: 32,
      },
    });

    // Grant SSO function access to this secret
    secret.grantRead(this.ssoFunction);
    
    // Store for reference
    this.applicationSecrets.set(config.name, secret);

    // Update SSO function environment with new application
    this.ssoFunction.addEnvironment(`${config.name.toUpperCase()}_SECRET_ARN`, secret.secretArn);
    this.ssoFunction.addEnvironment(`${config.name.toUpperCase()}_URL`, config.url);
    this.ssoFunction.addEnvironment(`${config.name.toUpperCase()}_ROLES`, config.allowedRoles.join(','));

    // Output the secret ARN for application deployment
    new cdk.CfnOutput(this, `${config.name}SecretArn`, {
      value: secret.secretArn,
      exportName: `Syml${config.name.charAt(0).toUpperCase() + config.name.slice(1)}SecretArn`,
      description: `${config.description} secret ARN`
    });
  }

  /**
   * Get application secret for integration
   */
  public getApplicationSecret(appName: string): secretsmanager.ISecret | undefined {
    return this.applicationSecrets.get(appName);
  }

  /**
   * Add custom application endpoints to the API
   */
  public addApplicationEndpoints(appName: string, endpoints: string[]): void {
    const appResource = this.api.root.addResource(appName);
    const integration = new apigateway.LambdaIntegration(this.ssoFunction);
    
    endpoints.forEach(endpoint => {
      const resource = appResource.addResource(endpoint);
      resource.addMethod('ANY', integration);
    });
  }

  /**
   * Enterprise application onboarding method
   * Call this to add new applications to the SSO system
   */
  public onboardApplication(config: ApplicationConfig): {
    secretArn: string;
    apiEndpoint: string;
    integrationGuide: string;
  } {
    this.registerApplication(config);
    
    const secret = this.getApplicationSecret(config.name);
    if (!secret) {
      throw new Error(`Failed to create secret for application: ${config.name}`);
    }

    return {
      secretArn: secret.secretArn,
      apiEndpoint: 'https://sso.syml.ai',
      integrationGuide: `
# ${config.description} Integration Guide

## Authentication Flow
1. User clicks access button in dashboard
2. Dashboard calls: GET https://sso.syml.ai/sso/generate-service-session?sessionId={sessionId}&service=${config.name}
3. SSO validates user role against allowed roles: [${config.allowedRoles.join(', ')}]
4. SSO creates service session and redirects to: ${config.url}?sessionId={serviceSessionId}
5. Your application validates session: POST https://sso.syml.ai/sso/validate-session

## Required Headers
- Content-Type: application/json

## Validation Payload
{
  "sessionId": "service-session-id-from-url",
  "service": "${config.name}",
  "appSecret": "retrieve-from-secrets-manager"
}

## Secret ARN
${secret.secretArn}

## Response Format
{
  "valid": true,
  "email": "user@example.com",
  "role": "admin|user",
  "sessionId": "session-id",
  "timeRemaining": 1800000
}
      `
    };
  }
}