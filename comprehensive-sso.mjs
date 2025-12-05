// comprehensive-sso.mjs - Enterprise SSO Service
// Consolidates: Login, MFA Setup, Session Validation, Dashboard Routing, QR Generation
// Single source of truth for all authentication

import {
  CognitoIdentityProviderClient,
  AdminInitiateAuthCommand,
  AdminRespondToAuthChallengeCommand,
  AdminSetUserMFAPreferenceCommand,
  AssociateSoftwareTokenCommand,
  VerifySoftwareTokenCommand,
  GetUserCommand
} from "@aws-sdk/client-cognito-identity-provider";

import {
  SecretsManagerClient,
  GetSecretValueCommand
} from "@aws-sdk/client-secrets-manager";

import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand
} from "@aws-sdk/client-dynamodb";

import {
  LambdaClient,
  InvokeCommand
} from "@aws-sdk/client-lambda";

import { randomUUID } from "crypto";

// Environment Configuration
const REGION = process.env.AWS_REGION || "us-east-1";
const USER_POOL_ID = process.env.USER_POOL_ID;
const COGNITO_CLIENT_SECRET_ARN = process.env.COGNITO_CLIENT_SECRET_ARN;
const MFA_SESSIONS_TABLE = process.env.MFA_SESSIONS_TABLE_NAME || "syml-mfa-sessions";
const AUDIT_TABLE = process.env.AUDIT_LOG_TABLE || "syml-audit-log";
const QR_GENERATOR_FUNCTION = process.env.QR_GENERATOR_FUNCTION || "syml-qr-generator";
const SCAN_APP_SECRET = process.env.SCAN_APP_SECRET;

// Session Configuration
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const WARNING_THRESHOLD_MS = 27 * 60 * 1000; // 27 minutes

// AWS Clients
const cognito = new CognitoIdentityProviderClient({ region: REGION });
const secrets = new SecretsManagerClient({ region: REGION });
const dynamodb = new DynamoDBClient({ region: REGION });
const lambda = new LambdaClient({ region: REGION });

// Utility Functions
async function getClientId() {
  const secret = await secrets.send(new GetSecretValueCommand({
    SecretId: COGNITO_CLIENT_SECRET_ARN
  }));
  const parsed = JSON.parse(secret.SecretString);
  return parsed.clientId;
}

async function logAuditEvent(eventType, sessionId, sourceIp, userAgent, result, email = null, service = null) {
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
        service: { S: service || 'syml-sso-service' }
      }
    }));
  } catch (err) {
    console.error('Audit logging failed:', err);
  }
}

async function generateQRCode(secret, email) {
  try {
    const payload = JSON.stringify({ secret, email, issuer: 'Syml' });
    const command = new InvokeCommand({
      FunctionName: QR_GENERATOR_FUNCTION,
      Payload: new TextEncoder().encode(payload)
    });
    const response = await lambda.send(command);
    const result = JSON.parse(new TextDecoder().decode(response.Payload));
    if (result.statusCode === 200) {
      const body = JSON.parse(result.body);
      return body.qr && body.qr.startsWith('data:image/png;base64,') ? body.qr : null;
    }
    return null;
  } catch (error) {
    console.error('QR generation error:', error);
    return null;
  }
}

function parseFormBody(event) {
  if (!event || !event.body) return {};
  let bodyString = event.body;
  if (event.isBase64Encoded) {
    bodyString = Buffer.from(bodyString, "base64").toString("utf-8");
  }
  const params = new URLSearchParams(bodyString);
  return Object.fromEntries(params.entries());
}

function redirectResponse(location, accessToken = null) {
  const headers = {
    "Content-Type": "text/html; charset=utf-8",
    Location: location,
    "Cache-Control": "no-cache"
  };

  if (accessToken) {
    headers["Set-Cookie"] = 
      `AccessToken=${accessToken}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600`;
  }

  return { statusCode: 302, headers, body: "" };
}

function getAccessTokenFromCookie(event) {
  const raw = event.headers?.cookie || event.headers?.Cookie;
  if (!raw) return null;
  const parts = raw.split(";");
  for (const p of parts) {
    const trimmed = p.trim();
    if (trimmed.startsWith("AccessToken=")) {
      return trimmed.replace("AccessToken=", "").trim();
    }
  }
  return null;
}

async function validateAndRefreshSession(sessionId, sourceIp, userAgent) {
  const result = await dynamodb.send(new GetItemCommand({
    TableName: MFA_SESSIONS_TABLE,
    Key: { sessionId: { S: sessionId } }
  }));

  if (!result.Item) {
    return { valid: false, error: 'Session not found' };
  }

  let expiry, email, role;
  if (result.Item.expiry) {
    expiry = parseInt(result.Item.expiry.N);
    email = result.Item.email.S;
    role = result.Item.role?.S || 'user';
  } else if (result.Item.expiresAt) {
    expiry = parseInt(result.Item.expiresAt.N) * 1000;
    email = result.Item.userId.S;
    role = result.Item.role?.S || 'user';
  } else {
    return { valid: false, error: 'Invalid session format' };
  }

  const now = Date.now();
  if (now > expiry) {
    await logAuditEvent('SESSION_EXPIRED', sessionId, sourceIp, userAgent, 'SESSION_EXPIRED', email);
    return { valid: false, error: 'Session expired' };
  }

  const timeRemaining = expiry - now;
  const needsWarning = timeRemaining <= (SESSION_TIMEOUT_MS - WARNING_THRESHOLD_MS);
  const newExpiry = now + SESSION_TIMEOUT_MS;
  
  try {
    await dynamodb.send(new UpdateItemCommand({
      TableName: MFA_SESSIONS_TABLE,
      Key: { sessionId: { S: sessionId } },
      UpdateExpression: result.Item.expiry ? 'SET expiry = :expiry, lastActivity = :activity' : 'SET expiresAt = :expiry, lastActivity = :activity',
      ExpressionAttributeValues: {
        ':expiry': { N: result.Item.expiry ? newExpiry.toString() : Math.floor(newExpiry / 1000).toString() },
        ':activity': { S: new Date().toISOString() }
      }
    }));
    await logAuditEvent('SESSION_REFRESHED', sessionId, sourceIp, userAgent, 'SESSION_EXTENDED', email);
  } catch (err) {
    console.error('Failed to refresh session:', err);
  }

  return { valid: true, email, role, sessionId, timeRemaining, needsWarning, newExpiry };
}

// Route Handlers
async function handleLogin(event, sourceIp, userAgent, corsHeaders) {
  const method = event.httpMethod || event.requestContext?.httpMethod;
  
  if (method === "GET") {
    // Check for existing session first
    const cookies = event.headers?.Cookie || event.headers?.cookie || '';
    const accessToken = getAccessTokenFromCookie(event);
    
    if (accessToken) {
      try {
        const userData = await cognito.send(new GetUserCommand({ AccessToken: accessToken }));
        const email = userData.UserAttributes.find(a => a.Name === "email")?.Value;
        await logAuditEvent('LOGIN_WITH_VALID_SESSION', null, sourceIp, userAgent, 'REDIRECT_TO_DASHBOARD', email);
        return redirectResponse('https://auth.syml.ai/dashboard-router');
      } catch (err) {
        console.log('Invalid access token, proceeding to login page');
      }
    }
    
    const error = event.queryStringParameters?.error;
    const message = event.queryStringParameters?.message;
    let redirectUrl = 'https://syml.ai/login.html';
    if (error) redirectUrl += `?error=${error}`;
    else if (message === 'mfa_setup_complete') redirectUrl += `?message=MFA setup complete. Please log in with your credentials.`;
    
    return redirectResponse(redirectUrl);
  }

  if (method === "POST") {
    const formData = parseFormBody(event);
    const { email, password, mfaCode, session } = formData;
    const clientId = await getClientId();

    // Handle MFA challenge
    if (session && mfaCode) {
      try {
        const resp = await cognito.send(new AdminRespondToAuthChallengeCommand({
          UserPoolId: USER_POOL_ID,
          ClientId: clientId,
          ChallengeName: "SOFTWARE_TOKEN_MFA",
          ChallengeResponses: {
            USERNAME: (email || "").trim().toLowerCase(),
            SOFTWARE_TOKEN_MFA_CODE: mfaCode
          },
          Session: session
        }));

        if (resp.AuthenticationResult?.AccessToken) {
          await logAuditEvent('MFA_LOGIN_SUCCESS', null, sourceIp, userAgent, 'ACCESS_GRANTED', email);
          return redirectResponse('https://auth.syml.ai/dashboard-router', resp.AuthenticationResult.AccessToken);
        }
        return redirectResponse('https://syml.ai/login.html?error=mfa_failed');
      } catch (error) {
        if (error.name === 'NotAuthorizedException' && error.message.includes('Software token MFA not enabled')) {
          const redirectUrl = `https://auth.syml.ai/mfa-setup?session=${session}&email=${encodeURIComponent(email)}`;
          return redirectResponse(redirectUrl);
        }
        await logAuditEvent('MFA_LOGIN_FAILED', null, sourceIp, userAgent, 'MFA_VERIFICATION_FAILED', email);
        return redirectResponse('https://syml.ai/login.html?error=mfa_failed');
      }
    }

    // Handle initial login
    if (!email || !password) {
      return redirectResponse('https://syml.ai/login.html?error=missing_credentials');
    }

    try {
      const loginAttempt = await cognito.send(new AdminInitiateAuthCommand({
        UserPoolId: USER_POOL_ID,
        ClientId: clientId,
        AuthFlow: "ADMIN_USER_PASSWORD_AUTH",
        AuthParameters: {
          USERNAME: email.trim().toLowerCase(),
          PASSWORD: password
        }
      }));

      const challenge = loginAttempt.ChallengeName;
      
      if (challenge === "MFA_SETUP") {
        const redirectUrl = `https://auth.syml.ai/mfa-setup?session=${loginAttempt.Session}&email=${encodeURIComponent(email)}`;
        return redirectResponse(redirectUrl);
      }

      if (challenge === "SOFTWARE_TOKEN_MFA") {
        const redirectUrl = `https://syml.ai/mfa.html?session=${loginAttempt.Session}&email=${encodeURIComponent(email)}`;
        return redirectResponse(redirectUrl);
      }

      if (loginAttempt.AuthenticationResult?.AccessToken) {
        await logAuditEvent('LOGIN_SUCCESS', null, sourceIp, userAgent, 'ACCESS_GRANTED', email);
        return redirectResponse('https://auth.syml.ai/dashboard-router', loginAttempt.AuthenticationResult.AccessToken);
      }

      return redirectResponse('https://syml.ai/login.html?error=auth_failed');
    } catch (err) {
      await logAuditEvent('LOGIN_FAILED', null, sourceIp, userAgent, err.name, email);
      if (err.name === 'NotAuthorizedException') return redirectResponse('https://syml.ai/login.html?error=invalid_credentials');
      if (err.name === 'UserNotFoundException') return redirectResponse('https://syml.ai/login.html?error=user_not_found');
      if (err.name === 'TooManyRequestsException') return redirectResponse('https://syml.ai/login.html?error=account_locked');
      return redirectResponse('https://syml.ai/login.html?error=server_error');
    }
  }

  return { statusCode: 405, headers: corsHeaders, body: JSON.stringify({ error: 'Method not allowed' }) };
}

async function handleMfaSetup(event, sourceIp, userAgent, corsHeaders) {
  const method = event.httpMethod || event.requestContext?.httpMethod;
  const session = event.queryStringParameters?.session;
  const email = event.queryStringParameters?.email;

  if (method === 'GET') {
    if (!session || !email) {
      return redirectResponse('https://auth.syml.ai/login?error=invalid_session');
    }

    try {
      const assoc = await cognito.send(new AssociateSoftwareTokenCommand({ Session: session }));
      const { SecretCode } = assoc;
      const qrCode = await generateQRCode(SecretCode, email);

      const params = new URLSearchParams({
        session: assoc.Session,
        email: email,
        secret: SecretCode
      });
      
      if (qrCode) params.append('qr', qrCode);

      await logAuditEvent('MFA_SETUP_INITIATED', null, sourceIp, userAgent, 'QR_CODE_GENERATED', email);
      return redirectResponse(`https://syml.ai/mfa-setup.html?${params.toString()}`);
    } catch (error) {
      await logAuditEvent('MFA_SETUP_FAILED', null, sourceIp, userAgent, 'QR_GENERATION_FAILED', email);
      return redirectResponse('https://auth.syml.ai/login?error=mfa_setup_failed');
    }
  }

  if (method === 'POST') {
    const formData = parseFormBody(event);
    const { session, email, mfaCode } = formData;

    if (!session || !mfaCode) {
      return redirectResponse('https://auth.syml.ai/login?error=missing_data');
    }

    try {
      await cognito.send(new VerifySoftwareTokenCommand({
        Session: session,
        UserCode: mfaCode,
        FriendlyDeviceName: "Authenticator App"
      }));

      await logAuditEvent('MFA_SETUP_COMPLETED', null, sourceIp, userAgent, 'MFA_ENABLED', email);
      return redirectResponse('https://auth.syml.ai/login?message=mfa_setup_complete');
    } catch (error) {
      await logAuditEvent('MFA_SETUP_FAILED', null, sourceIp, userAgent, 'VERIFICATION_FAILED', email);
      return redirectResponse('https://auth.syml.ai/login?error=mfa_setup_failed');
    }
  }

  return { statusCode: 405, headers: corsHeaders, body: JSON.stringify({ error: 'Method not allowed' }) };
}

async function handleDashboardRouter(event, sourceIp, userAgent, corsHeaders) {
  const accessToken = getAccessTokenFromCookie(event);

  if (!accessToken) {
    return redirectResponse('https://auth.syml.ai/login');
  }

  try {
    const userData = await cognito.send(new GetUserCommand({ AccessToken: accessToken }));
    const username = userData.Username;
    
    let userRole = "customer";
    const roleAttr = userData.UserAttributes.find(a => a.Name === "custom:role");
    if (roleAttr && roleAttr.Value === "admin") userRole = "admin";

    const sessionId = randomUUID();
    const email = userData.UserAttributes.find(a => a.Name === "email")?.Value || username;
    const expiry = Date.now() + SESSION_TIMEOUT_MS;

    await dynamodb.send(new PutItemCommand({
      TableName: MFA_SESSIONS_TABLE,
      Item: {
        sessionId: { S: sessionId },
        email: { S: email },
        accessToken: { S: accessToken },
        expiry: { N: expiry.toString() },
        role: { S: userRole }
      }
    }));

    const redirectUrl = userRole === "admin" 
      ? "https://lms.syml.ai" 
      : `https://auth.syml.ai/customer?sessionId=${sessionId}`;

    await logAuditEvent('DASHBOARD_ROUTING', sessionId, sourceIp, userAgent, `${userRole.toUpperCase()}_ACCESS`, email);
    return redirectResponse(redirectUrl);
  } catch (err) {
    await logAuditEvent('DASHBOARD_ROUTING_FAILED', null, sourceIp, userAgent, 'TOKEN_VALIDATION_FAILED');
    const expiredCookie = "AccessToken=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax;";
    return {
      statusCode: 302,
      headers: {
        Location: 'https://auth.syml.ai/login',
        "Set-Cookie": expiredCookie,
        "Cache-Control": "no-cache"
      },
      body: ""
    };
  }
}

async function handleSessionValidation(event, sourceIp, userAgent, corsHeaders) {
  const body = JSON.parse(event.body || '{}');
  const { sessionId, service, appSecret } = body;

  // Validate app secret for scan app
  if (appSecret && appSecret !== SCAN_APP_SECRET) {
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

  const validation = await validateAndRefreshSession(sessionId, sourceIp, userAgent);
  
  if (!validation.valid) {
    await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, validation.error);
    return {
      statusCode: 401,
      headers: corsHeaders,
      body: JSON.stringify({ error: validation.error })
    };
  }

  await logAuditEvent('SESSION_VALIDATION_SUCCESS', sessionId, sourceIp, userAgent, 'ACCESS_GRANTED', validation.email, service);
  
  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({
      valid: true,
      email: validation.email,
      role: validation.role,
      sessionId: validation.sessionId,
      timeRemaining: validation.timeRemaining,
      needsWarning: validation.needsWarning
    })
  };
}

// Main Handler
export const handler = async (event) => {
  const sourceIp = event.requestContext?.identity?.sourceIp || event.headers?.['X-Forwarded-For'] || 'unknown';
  const userAgent = event.headers?.['User-Agent'] || 'unknown';
  
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Content-Type': 'application/json'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: corsHeaders, body: '' };
  }

  try {
    const path = event.path || event.requestContext?.path || '';
    
    if (path.includes('/login')) {
      return await handleLogin(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/mfa-setup')) {
      return await handleMfaSetup(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/dashboard-router')) {
      return await handleDashboardRouter(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/validate-session')) {
      return await handleSessionValidation(event, sourceIp, userAgent, corsHeaders);
    }

    return {
      statusCode: 404,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Endpoint not found' })
    };

  } catch (err) {
    console.error('SSO Service error:', err);
    await logAuditEvent('SSO_SERVICE_ERROR', 'unknown', sourceIp, userAgent, `SYSTEM_ERROR: ${err.message}`);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Service unavailable' })
    };
  }
};