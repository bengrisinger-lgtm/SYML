// index.mjs - Session Validator for Scan App
// Bank-level security validation

import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const REGION = process.env.AWS_REGION || "us-east-1";
const dynamodb = new DynamoDBClient({ region: REGION });
const secrets = new SecretsManagerClient({ region: REGION });
const AUDIT_TABLE = process.env.AUDIT_LOG_TABLE || "syml-audit-log";
const SCAN_SECRET_ARN = process.env.SCAN_SECRET_ARN || 'arn:aws:secretsmanager:us-east-1:644238524155:secret:syml-scan-app-secret';

// Cache for rotated secrets
const secretCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

async function getScanAppSecret() {
  const cached = secretCache.get(SCAN_SECRET_ARN);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
    return cached.secret;
  }

  try {
    const secret = await secrets.send(new GetSecretValueCommand({
      SecretId: SCAN_SECRET_ARN
    }));
    const parsed = JSON.parse(secret.SecretString);
    const appSecret = parsed.appSecret;
    
    secretCache.set(SCAN_SECRET_ARN, {
      secret: appSecret,
      timestamp: Date.now()
    });
    
    return appSecret;
  } catch (error) {
    console.error('Failed to retrieve scan app secret:', error);
    // Fallback to environment variable for backward compatibility
    return process.env.SCAN_APP_SECRET;
  }
}

// Audit logging for bank-level security compliance
async function logAuditEvent(eventType, sessionId, sourceIp, userAgent, result, email = null) {
  try {
    await dynamodb.send(new PutItemCommand({
      TableName: AUDIT_TABLE,
      Item: {
        auditId: { S: `${Date.now()}-${Math.random().toString(36).substr(2, 9)}` },
        timestamp: { S: new Date().toISOString() },
        eventType: { S: eventType },
        sessionId: { S: sessionId || 'unknown' },
        sourceIp: { S: sourceIp || 'unknown' },
        userAgent: { S: (userAgent || 'unknown').substring(0, 500) },
        result: { S: result },
        email: { S: email || 'unknown' },
        service: { S: 'syml-scan-validator' }
      }
    }));
  } catch (err) {
    console.error('Audit logging failed:', err);
  }
}

export const handler = async (event) => {
  const sourceIp = event.requestContext?.identity?.sourceIp || event.headers?.['X-Forwarded-For'] || 'unknown';
  const userAgent = event.headers?.['User-Agent'] || 'unknown';
  
  // CORS headers for cross-origin requests
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Content-Type': 'application/json'
  };

  // Handle preflight OPTIONS request
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: ''
    };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const { sessionId, appSecret } = body;

    // Validate app secret with rotatable secret from Secrets Manager
    const expectedSecret = await getScanAppSecret();
    if (!appSecret || appSecret !== expectedSecret) {
      await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'INVALID_APP_SECRET');
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Invalid app credentials' })
      };
    }

    if (!sessionId) {
      await logAuditEvent('SESSION_VALIDATION_FAILED', null, sourceIp, userAgent, 'MISSING_SESSION_ID');
      return {
        statusCode: 400,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Session ID required' })
      };
    }

    // Validate session
    const result = await dynamodb.send(new GetItemCommand({
      TableName: process.env.MFA_SESSIONS_TABLE_NAME || "syml-mfa-sessions",
      Key: { sessionId: { S: sessionId } }
    }));

    if (!result.Item) {
      await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'SESSION_NOT_FOUND');
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Invalid session' })
      };
    }

    // Handle both session formats: dashboard sessions (expiry/email) and scan sessions (expiresAt/userId)
    let expiry, email;
    if (result.Item.expiry) {
      expiry = parseInt(result.Item.expiry.N);
      email = result.Item.email.S;
    } else if (result.Item.expiresAt) {
      expiry = parseInt(result.Item.expiresAt.N) * 1000;
      email = result.Item.userId.S;
    } else {
      await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'INVALID_SESSION_FORMAT');
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Invalid session format' })
      };
    }
    
    if (Date.now() > expiry) {
      await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'SESSION_EXPIRED', email);
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Session expired' })
      };
    }

    // Log successful validation
    await logAuditEvent('SESSION_VALIDATION_SUCCESS', sessionId, sourceIp, userAgent, 'ACCESS_GRANTED', email);
    
    // Return user info for scan app
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({
        valid: true,
        email: email,
        sessionId: sessionId
      })
    };

  } catch (err) {
    console.error('Session validation error:', err);
    const sessionIdForLog = event.body ? JSON.parse(event.body).sessionId || 'unknown' : 'unknown';
    await logAuditEvent('SESSION_VALIDATION_ERROR', sessionIdForLog, sourceIp, userAgent, `SYSTEM_ERROR: ${err.message}`);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Validation failed' })
    };
  }
};