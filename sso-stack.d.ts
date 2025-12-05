import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';
export declare class SSOStack extends cdk.Stack {
    readonly userPool: cognito.IUserPool;
    readonly api: apigateway.RestApi;
    readonly sessionsTable: dynamodb.ITable;
    constructor(scope: Construct, id: string, props?: cdk.StackProps);
    addApplicationClient(appName: string): cognito.UserPoolClient;
}
