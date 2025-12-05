"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SSOStack = void 0;
const cdk = require("aws-cdk-lib");
const cognito = require("aws-cdk-lib/aws-cognito");
const lambda = require("aws-cdk-lib/aws-lambda");
const apigateway = require("aws-cdk-lib/aws-apigateway");
const dynamodb = require("aws-cdk-lib/aws-dynamodb");
const secretsmanager = require("aws-cdk-lib/aws-secretsmanager");
class SSOStack extends cdk.Stack {
    constructor(scope, id, props) {
        super(scope, id, props);
        // 1. Import existing User Pool from CloudFormation
        this.userPool = cognito.UserPool.fromUserPoolId(this, 'ExistingUserPool', 'us-east-1_59Mcy7HO3');
        // 2. Import existing App Clients
        const scanClient = cognito.UserPoolClient.fromUserPoolClientId(this, 'ExistingScanClient', '792pi2b5tl7cur7toeo8kmbs00');
        const lmsClient = this.userPool.addClient('LmsClient', {
            userPoolClientName: 'Syml-LMS-App',
            generateSecret: true,
            authFlows: { userPassword: true, userSrp: true },
        });
        // 3. RBAC Groups (already exist, skip creation)
        // 4. Reference existing tables
        this.sessionsTable = dynamodb.Table.fromTableName(this, 'SessionsTable', 'syml-mfa-sessions');
        const auditTable = dynamodb.Table.fromTableName(this, 'AuditTable', 'syml-audit-log');
        // 6. Import existing LMS secret, create scan secret if needed
        const lmsSecret = secretsmanager.Secret.fromSecretCompleteArn(this, 'ExistingLmsSecret', 'arn:aws:secretsmanager:us-east-1:644238524155:secret:syml-lms-app-secret-Qro2za');
        const scanSecret = new secretsmanager.Secret(this, 'ScanAppSecret', {
            secretName: 'syml-scan-app-secret',
            generateSecretString: {
                secretStringTemplate: JSON.stringify({}),
                generateStringKey: 'appSecret',
                excludeCharacters: '"@/\\',
                passwordLength: 32,
            },
        });
        // 7. SSO Lambda Function
        const ssoFunction = new lambda.Function(this, 'SSOFunction', {
            functionName: 'syml-sso-service',
            runtime: lambda.Runtime.NODEJS_20_X,
            handler: 'index.handler',
            code: lambda.Code.fromAsset('../syml-sso-service'),
            timeout: cdk.Duration.seconds(30),
            memorySize: 256,
            environment: {
                USER_POOL_ID: this.userPool.userPoolId,
                SESSIONS_TABLE: this.sessionsTable.tableName,
                AUDIT_TABLE: auditTable.tableName,
                SCAN_SECRET_ARN: scanSecret.secretArn,
                LMS_SECRET_ARN: lmsSecret.secretArn,
            },
        });
        // 8. IAM Permissions
        this.userPool.grant(ssoFunction, 'cognito-idp:*');
        this.sessionsTable.grantReadWriteData(ssoFunction);
        auditTable.grantWriteData(ssoFunction);
        scanSecret.grantRead(ssoFunction);
        lmsSecret.grantRead(ssoFunction);
        // 9. API Gateway
        this.api = new apigateway.RestApi(this, 'SSOApi', {
            restApiName: 'Syml SSO Service',
            description: 'Enterprise SSO API',
            defaultCorsPreflightOptions: {
                allowOrigins: apigateway.Cors.ALL_ORIGINS,
                allowMethods: apigateway.Cors.ALL_METHODS,
                allowHeaders: ['Content-Type', 'Authorization'],
            },
        });
        const ssoIntegration = new apigateway.LambdaIntegration(ssoFunction);
        // SSO Endpoints
        const sso = this.api.root.addResource('sso');
        sso.addResource('login').addMethod('POST', ssoIntegration);
        sso.addResource('generate-service-session').addMethod('GET', ssoIntegration);
        sso.addResource('validate-session').addMethod('POST', ssoIntegration);
        sso.addResource('get-service-secret').addMethod('GET', ssoIntegration);
        // 10. Outputs for Application Integration
        new cdk.CfnOutput(this, 'UserPoolId', {
            value: this.userPool.userPoolId,
            exportName: 'SymlUserPoolId',
        });
        new cdk.CfnOutput(this, 'ScanClientId', {
            value: scanClient.userPoolClientId,
            exportName: 'SymlScanClientId',
        });
        new cdk.CfnOutput(this, 'LmsClientId', {
            value: lmsClient.userPoolClientId,
            exportName: 'SymlLmsClientId',
        });
        new cdk.CfnOutput(this, 'SSOApiUrl', {
            value: this.api.url,
            exportName: 'SymlSSOApiUrl',
        });
    }
    // Method to add new application clients
    addApplicationClient(appName) {
        return this.userPool.addClient(`${appName}Client`, {
            userPoolClientName: `Syml-${appName}-App`,
            generateSecret: true,
            authFlows: { userPassword: true, userSrp: true },
        });
    }
}
exports.SSOStack = SSOStack;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic3NvLXN0YWNrLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsic3NvLXN0YWNrLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7OztBQUFBLG1DQUFtQztBQUNuQyxtREFBbUQ7QUFDbkQsaURBQWlEO0FBQ2pELHlEQUF5RDtBQUN6RCxxREFBcUQ7QUFDckQsaUVBQWlFO0FBSWpFLE1BQWEsUUFBUyxTQUFRLEdBQUcsQ0FBQyxLQUFLO0lBTXJDLFlBQVksS0FBZ0IsRUFBRSxFQUFVLEVBQUUsS0FBc0I7UUFDOUQsS0FBSyxDQUFDLEtBQUssRUFBRSxFQUFFLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFFeEIsbURBQW1EO1FBQ25ELElBQUksQ0FBQyxRQUFRLEdBQUcsT0FBTyxDQUFDLFFBQVEsQ0FBQyxjQUFjLENBQUMsSUFBSSxFQUFFLGtCQUFrQixFQUFFLHFCQUFxQixDQUFDLENBQUM7UUFFakcsaUNBQWlDO1FBQ2pDLE1BQU0sVUFBVSxHQUFHLE9BQU8sQ0FBQyxjQUFjLENBQUMsb0JBQW9CLENBQUMsSUFBSSxFQUFFLG9CQUFvQixFQUFFLDRCQUE0QixDQUFDLENBQUM7UUFDekgsTUFBTSxTQUFTLEdBQUcsSUFBSSxDQUFDLFFBQVEsQ0FBQyxTQUFTLENBQUMsV0FBVyxFQUFFO1lBQ3JELGtCQUFrQixFQUFFLGNBQWM7WUFDbEMsY0FBYyxFQUFFLElBQUk7WUFDcEIsU0FBUyxFQUFFLEVBQUUsWUFBWSxFQUFFLElBQUksRUFBRSxPQUFPLEVBQUUsSUFBSSxFQUFFO1NBQ2pELENBQUMsQ0FBQztRQUVILGdEQUFnRDtRQUVoRCwrQkFBK0I7UUFDL0IsSUFBSSxDQUFDLGFBQWEsR0FBRyxRQUFRLENBQUMsS0FBSyxDQUFDLGFBQWEsQ0FBQyxJQUFJLEVBQUUsZUFBZSxFQUFFLG1CQUFtQixDQUFDLENBQUM7UUFDOUYsTUFBTSxVQUFVLEdBQUcsUUFBUSxDQUFDLEtBQUssQ0FBQyxhQUFhLENBQUMsSUFBSSxFQUFFLFlBQVksRUFBRSxnQkFBZ0IsQ0FB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YXdzLWNkay1saWInO1xuaW1wb3J0ICogYXMgY29nbml0byBmcm9tICdhd3MtY2RrLWxpYi9hd3MtY29nbml0byc7XG5pbXBvcnQgKiBhcyBsYW1iZGEgZnJvbSAnYXdzLWNkay1saWIvYXdzLWxhbWJkYSc7XG5pbXBvcnQgKiBhcyBhcGlnYXRld2F5IGZyb20gJ2F3cy1jZGstbGliL2F3cy1hcGlnYXRld2F5JztcbmltcG9ydCAqIGFzIGR5bmFtb2RiIGZyb20gJ2F3cy1jZGstbGliL2F3cy1keW5hbW9kYic7XG5pbXBvcnQgKiBhcyBzZWNyZXRzbWFuYWdlciBmcm9tICdhd3MtY2RrLWxpYi9hd3Mtc2VjcmV0c21hbmFnZXInO1xuaW1wb3J0ICogYXMgaWFtIGZyb20gJ2F3cy1jZGstbGliL2F3cy1pYW0nO1xuaW1wb3J0IHsgQ29uc3RydWN0IH0gZnJvbSAnY29uc3RydWN0cyc7XG5cbmV4cG9ydCBjbGFzcyBTU09TdGFjayBleHRlbmRzIGNkay5TdGFjayB7XG4gIC8vIEV4cG9zZSBjb3JlIHJlc291cmNlcyBmb3IgY3Jvc3Mtc3RhY2sgcmVmZXJlbmNpbmdcbiAgcHVibGljIHJlYWRvbmx5IHVzZXJQb29sOiBjb2duaXRvLklVc2VyUG9vbDtcbiAgcHVibGljIHJlYWRvbmx5IGFwaTogYXBpZ2F0ZXdheS5SZXN0QXBpO1xuICBwdWJsaWMgcmVhZG9ubHkgc2Vzc2lvbnNUYWJsZTogZHluYW1vZGIuSVRhYmxlO1xuXG4gIGNvbnN0cnVjdG9yKHNjb3BlOiBDb25zdHJ1Y3QsIGlkOiBzdHJpbmcsIHByb3BzPzogY2RrLlN0YWNrUHJvcHMpIHtcbiAgICBzdXBlcihzY29wZSwgaWQsIHByb3BzKTtcblxuICAgIC8vIDEuIEltcG9ydCBleGlzdGluZyBVc2VyIFBvb2wgZnJvbSBDbG91ZEZvcm1hdGlvblxuICAgIHRoaXMudXNlclBvb2wgPSBjb2duaXRvLlVzZXJQb29sLmZyb21Vc2VyUG9vbElkKHRoaXMsICdFeGlzdGluZ1VzZXJQb29sJywgJ3VzLWVhc3QtMV81OU1jeTdITzMnKTtcblxuICAgIC8vIDIuIEltcG9ydCBleGlzdGluZyBBcHAgQ2xpZW50c1xuICAgIGNvbnN0IHNjYW5DbGllbnQgPSBjb2duaXRvLlVzZXJQb29sQ2xpZW50LmZyb21Vc2VyUG9vbENsaWVudElkKHRoaXMsICdFeGlzdGluZ1NjYW5DbGllbnQnLCAnNzkycGkyYjV0bDdjdXI3dG9lbzhrbWJzMDAnKTtcbiAgICBjb25zdCBsbXNDbGllbnQgPSB0aGlzLnVzZXJQb29sLmFkZENsaWVudCgnTG1zQ2xpZW50Jywge1xuICAgICAgdXNlclBvb2xDbGllbnROYW1lOiAnU3ltbC1MTVMtQXBwJywgXG4gICAgICBnZW5lcmF0ZVNlY3JldDogdHJ1ZSxcbiAgICAgIGF1dGhGbG93czogeyB1c2VyUGFzc3dvcmQ6IHRydWUsIHVzZXJTcnA6IHRydWUgfSxcbiAgICB9KTtcblxuICAgIC8vIDMuIFJCQUMgR3JvdXBzIChhbHJlYWR5IGV4aXN0LCBza2lwIGNyZWF0aW9uKVxuXG4gICAgLy8gNC4gUmVmZXJlbmNlIGV4aXN0aW5nIHRhYmxlc1xuICAgIHRoaXMuc2Vzc2lvbnNUYWJsZSA9IGR5bmFtb2RiLlRhYmxlLmZyb21UYWJsZU5hbWUodGhpcywgJ1Nlc3Npb25zVGFibGUnLCAnc3ltbC1tZmEtc2Vzc2lvbnMnKTtcbiAgICBjb25zdCBhdWRpdFRhYmxlID0gZHluYW1vZGIuVGFibGUuZnJvbVRhYmxlTmFtZSh0aGlzLCAnQXVkaXRUYWJsZScsICdzeW1sLWF1ZGl0LWxvZycpO1xuXG4gICAgLy8gNi4gSW1wb3J0IGV4aXN0aW5nIExNUyBzZWNyZXQsIGNyZWF0ZSBzY2FuIHNlY3JldCBpZiBuZWVkZWRcbiAgICBjb25zdCBsbXNTZWNyZXQgPSBzZWNyZXRzbWFuYWdlci5TZWNyZXQuZnJvbVNlY3JldENvbXBsZXRlQXJuKHRoaXMsICdFeGlzdGluZ0xtc1NlY3JldCcsICdhcm46YXdzOnNlY3JldHNtYW5hZ2VyOnVzLWVhc3QtMTo2NDQyMzg1MjQxNTU6c2VjcmV0OnN5bWwtbG1zLWFwcC1zZWNyZXQtUXJvMnphJyk7XG4gICAgXG4gICAgY29uc3Qgc2NhblNlY3JldCA9IG5ldyBzZWNyZXRzbWFuYWdlci5TZWNyZXQodGhpcywgJ1NjYW5BcHBTZWNyZXQnLCB7XG4gICAgICBzZWNyZXROYW1lOiAnc3ltbC1zY2FuLWFwcC1zZWNyZXQnLFxuICAgICAgZ2VuZXJhdGVTZWNyZXRTdHJpbmc6IHtcbiAgICAgICAgc2VjcmV0U3RyaW5nVGVtcGxhdGU6IEpTT04uc3RyaW5naWZ5KHt9KSxcbiAgICAgICAgZ2VuZXJhdGVTdHJpbmdLZXk6ICdhcHBTZWNyZXQnLFxuICAgICAgICBleGNsdWRlQ2hhcmFjdGVyczogJ1wiQC9cXFxcJyxcbiAgICAgICAgcGFzc3dvcmRMZW5ndGg6IDMyLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIDcuIFNTTyBMYW1iZGEgRnVuY3Rpb25cbiAgICBjb25zdCBzc29GdW5jdGlvbiA9IG5ldyBsYW1iZGEuRnVuY3Rpb24odGhpcywgJ1NTT0Z1bmN0aW9uJywge1xuICAgICAgZnVuY3Rpb25OYW1lOiAnc3ltbC1zc28tc2VydmljZScsXG4gICAgICBydW50aW1lOiBsYW1iZGEuUnVudGltZS5OT0RFSlNfMjBfWCxcbiAgICAgIGhhbmRsZXI6ICdpbmRleC5oYW5kbGVyJyxcbiAgICAgIGNvZGU6IGxhbWJkYS5Db2RlLmZyb21Bc3NldCgnLi4vc3ltbC1zc28tc2VydmljZScpLFxuICAgICAgdGltZW91dDogY2RrLkR1cmF0aW9uLnNlY29uZHMoMzApLFxuICAgICAgbWVtb3J5U2l6ZTogMjU2LFxuICAgICAgZW52aXJvbm1lbnQ6IHtcbiAgICAgICAgVVNFUl9QT09MX0lEOiB0aGlzLnVzZXJQb29sLnVzZXJQb29sSWQsXG4gICAgICAgIFNFU1NJT05TX1RBQkxFOiB0aGlzLnNlc3Npb25zVGFibGUudGFibGVOYW1lLFxuICAgICAgICBBVURJVF9UQUJMRTogYXVkaXRUYWJsZS50YWJsZU5hbWUsXG4gICAgICAgIFNDQU5fU0VDUkVUX0FSTjogc2NhblNlY3JldC5zZWNyZXRBcm4sXG4gICAgICAgIExNU19TRUNSRVRfQVJOOiBsbXNTZWNyZXQuc2VjcmV0QXJuLFxuICAgICAgfSxcbiAgICB9KTtcblxuICAgIC8vIDguIElBTSBQZXJtaXNzaW9uc1xuICAgIHRoaXMudXNlclBvb2wuZ3JhbnQoc3NvRnVuY3Rpb24sICdjb2duaXRvLWlkcDoqJyk7XG4gICAgdGhpcy5zZXNzaW9uc1RhYmxlLmdyYW50UmVhZFdyaXRlRGF0YShzc29GdW5jdGlvbik7XG4gICAgYXVkaXRUYWJsZS5ncmFudFdyaXRlRGF0YShzc29GdW5jdGlvbik7XG4gICAgc2NhblNlY3JldC5ncmFudFJlYWQoc3NvRnVuY3Rpb24pO1xuICAgIGxtc1NlY3JldC5ncmFudFJlYWQoc3NvRnVuY3Rpb24pO1xuXG4gICAgLy8gOS4gQVBJIEdhdGV3YXlcbiAgICB0aGlzLmFwaSA9IG5ldyBhcGlnYXRld2F5LlJlc3RBcGkodGhpcywgJ1NTT0FwaScsIHtcbiAgICAgIHJlc3RBcGlOYW1lOiAnU3ltbCBTU08gU2VydmljZScsXG4gICAgICBkZXNjcmlwdGlvbjogJ0VudGVycHJpc2UgU1NPIEFQSScsXG4gICAgICBkZWZhdWx0Q29yc1ByZWZsaWdodE9wdGlvbnM6IHtcbiAgICAgICAgYWxsb3dPcmlnaW5zOiBhcGlnYXRld2F5LkNvcnMuQUxMX09SSUdJTlMsXG4gICAgICAgIGFsbG93TWV0aG9kczogYXBpZ2F0ZXdheS5Db3JzLkFMTF9NRVRIT0RTLFxuICAgICAgICBhbGxvd0hlYWRlcnM6IFsnQ29udGVudC1UeXBlJywgJ0F1dGhvcml6YXRpb24nXSxcbiAgICAgIH0sXG4gICAgfSk7XG5cbiAgICBjb25zdCBzc29JbnRlZ3JhdGlvbiA9IG5ldyBhcGlnYXRld2F5LkxhbWJkYUludGVncmF0aW9uKHNzb0Z1bmN0aW9uKTtcblxuICAgIC8vIFNTTyBFbmRwb2ludHNcbiAgICBjb25zdCBzc28gPSB0aGlzLmFwaS5yb290LmFkZFJlc291cmNlKCdzc28nKTtcbiAgICBzc28uYWRkUmVzb3VyY2UoJ2xvZ2luJykuYWRkTWV0aG9kKCdQT1NUJywgc3NvSW50ZWdyYXRpb24pO1xuICAgIHNzby5hZGRSZXNvdXJjZSgnZ2VuZXJhdGUtc2VydmljZS1zZXNzaW9uJykuYWRkTWV0aG9kKCdHRVQnLCBzc29JbnRlZ3JhdGlvbik7XG4gICAgc3NvLmFkZFJlc291cmNlKCd2YWxpZGF0ZS1zZXNzaW9uJykuYWRkTWV0aG9kKCdQT1NUJywgc3NvSW50ZWdyYXRpb24pO1xuICAgIHNzby5hZGRSZXNvdXJjZSgnZ2V0LXNlcnZpY2Utc2VjcmV0JykuYWRkTWV0aG9kKCdHRVQnLCBzc29JbnRlZ3JhdGlvbik7XG5cbiAgICAvLyAxMC4gT3V0cHV0cyBmb3IgQXBwbGljYXRpb24gSW50ZWdyYXRpb25cbiAgICBuZXcgY2RrLkNmbk91dHB1dCh0aGlzLCAnVXNlclBvb2xJZCcsIHtcbiAgICAgIHZhbHVlOiB0aGlzLnVzZXJQb29sLnVzZXJQb29sSWQsXG4gICAgICBleHBvcnROYW1lOiAnU3ltbFVzZXJQb29sSWQnLFxuICAgIH0pO1xuXG4gICAgbmV3IGNkay5DZm5PdXRwdXQodGhpcywgJ1NjYW5DbGllbnRJZCcsIHtcbiAgICAgIHZhbHVlOiBzY2FuQ2xpZW50LnVzZXJQb29sQ2xpZW50SWQsXG4gICAgICBleHBvcnROYW1lOiAnU3ltbFNjYW5DbGllbnRJZCcsXG4gICAgfSk7XG5cbiAgICBuZXcgY2RrLkNmbk91dHB1dCh0aGlzLCAnTG1zQ2xpZW50SWQnLCB7XG4gICAgICB2YWx1ZTogbG1zQ2xpZW50LnVzZXJQb29sQ2xpZW50SWQsXG4gICAgICBleHBvcnROYW1lOiAnU3ltbExtc0NsaWVudElkJyxcbiAgICB9KTtcblxuICAgIG5ldyBjZGsuQ2ZuT3V0cHV0KHRoaXMsICdTU09BcGlVcmwnLCB7XG4gICAgICB2YWx1ZTogdGhpcy5hcGkudXJsLFxuICAgICAgZXhwb3J0TmFtZTogJ1N5bWxTU09BcGlVcmwnLFxuICAgIH0pO1xuICB9XG5cbiAgLy8gTWV0aG9kIHRvIGFkZCBuZXcgYXBwbGljYXRpb24gY2xpZW50c1xuICBwdWJsaWMgYWRkQXBwbGljYXRpb25DbGllbnQoYXBwTmFtZTogc3RyaW5nKTogY29nbml0by5Vc2VyUG9vbENsaWVudCB7XG4gICAgcmV0dXJuIHRoaXMudXNlclBvb2wuYWRkQ2xpZW50KGAke2FwcE5hbWV9Q2xpZW50YCwge1xuICAgICAgdXNlclBvb2xDbGllbnROYW1lOiBgU3ltbC0ke2FwcE5hbWV9LUFwcGAsXG4gICAgICBnZW5lcmF0ZVNlY3JldDogdHJ1ZSxcbiAgICAgIGF1dGhGbG93czogeyB1c2VyUGFzc3dvcmQ6IHRydWUsIHVzZXJTcnA6IHRydWUgfSxcbiAgICB9KTtcbiAgfVxufSJdfQ==