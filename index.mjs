// index.mjs - Comprehensive SSO Service
// Consolidates: Login, MFA Setup, Session Validation, Dashboard Routing
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
const LMS_APP_SECRET_ARN = 'arn:aws:secretsmanager:us-east-1:644238524155:secret:syml-lms-app-secret-Qro2za';
const SCAN_APP_SECRET = process.env.SCAN_APP_SECRET;

// Service secret mapping for enterprise-grade security
const SERVICE_SECRETS = {
  'scan': { type: 'env', value: SCAN_APP_SECRET }, // Legacy env var
  'lms': { type: 'secrets', arn: LMS_APP_SECRET_ARN },
  'crm': { type: 'secrets', arn: LMS_APP_SECRET_ARN } // CRM uses LMS secret
};

// Cache for rotated secrets (enterprise requirement)
const secretCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Enterprise-grade secret retrieval with rotation support
async function getServiceSecret(service) {
  const config = SERVICE_SECRETS[service];
  if (!config) {
    throw new Error(`Unknown service: ${service}`);
  }

  if (config.type === 'env') {
    return config.value;
  }

  // Handle AWS Secrets Manager with caching for performance
  const cacheKey = config.arn;
  const cached = secretCache.get(cacheKey);
  
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
    return cached.secret;
  }

  try {
    const secret = await secrets.send(new GetSecretValueCommand({
      SecretId: config.arn
    }));
    const parsed = JSON.parse(secret.SecretString);
    const appSecret = parsed.appSecret;
    
    // Cache for performance while maintaining security
    secretCache.set(cacheKey, {
      secret: appSecret,
      timestamp: Date.now()
    });
    
    return appSecret;
  } catch (error) {
    console.error(`Failed to retrieve secret for service ${service}:`, error);
    throw new Error('Secret retrieval failed');
  }
}

// AWS Clients
const cognito = new CognitoIdentityProviderClient({ region: REGION });
const secrets = new SecretsManagerClient({ region: REGION });
const dynamodb = new DynamoDBClient({ region: REGION });
const lambda = new LambdaClient({ region: REGION });

// Session timeout configuration
const SESSION_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes
const WARNING_THRESHOLD_MS = 27 * 60 * 1000; // 27 minutes (3 min warning)

// Utility Functions
async function getClientId() {
  const secret = await secrets.send(new GetSecretValueCommand({
    SecretId: COGNITO_CLIENT_SECRET_ARN
  }));
  const parsed = JSON.parse(secret.SecretString);
  return parsed.clientId;
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

// Audit logging for bank-level security compliance
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

// Generate secure session token for service access
function generateServiceToken(sessionId, service, email) {
  const payload = {
    sessionId,
    service,
    email,
    timestamp: Date.now(),
    expires: Date.now() + SESSION_TIMEOUT_MS
  };
  
  // In production, this should be JWT signed with a secret
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

// Validate and refresh session
async function validateAndRefreshSession(sessionId, sourceIp, userAgent) {
  const result = await dynamodb.send(new GetItemCommand({
    TableName: MFA_SESSIONS_TABLE,
    Key: { sessionId: { S: sessionId } }
  }));

  if (!result.Item) {
    return { valid: false, error: 'Session not found' };
  }

  // Handle both session formats
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

  // Calculate time remaining
  const timeRemaining = expiry - now;
  const needsWarning = timeRemaining <= (SESSION_TIMEOUT_MS - WARNING_THRESHOLD_MS);

  // Refresh session expiry (extend by 30 minutes from now)
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

  return {
    valid: true,
    email,
    role,
    sessionId,
    timeRemaining,
    needsWarning,
    newExpiry
  };
}

export const handler = async (event) => {
  const sourceIp = event.requestContext?.identity?.sourceIp || event.headers?.['X-Forwarded-For'] || 'unknown';
  const userAgent = event.headers?.['User-Agent'] || 'unknown';
  
  // CORS headers
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
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
    const path = event.path || event.requestContext?.path || '';
    const method = event.httpMethod;

    // Route handling
    if (path.includes('/login')) {
      return await handleLogin(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/mfa-setup')) {
      return await handleMfaSetup(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/dashboard-router')) {
      return await handleDashboardRouter(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/validate-session') && method === 'POST') {
      return await handleSessionValidation(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/generate-service-session') && method === 'GET') {
      return await handleServiceSessionGeneration(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/refresh-session') && method === 'POST') {
      return await handleSessionRefresh(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/logout') && method === 'POST') {
      return await handleLogout(event, sourceIp, userAgent, corsHeaders);
    }
    
    if (path.includes('/get-service-secret') && method === 'GET') {
      return await handleGetServiceSecret(event, sourceIp, userAgent, corsHeaders);
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

// Handle session validation using enterprise-grade security
async function handleSessionValidation(event, sourceIp, userAgent, corsHeaders) {
  const body = JSON.parse(event.body || '{}');
  const { sessionId, service, appSecret } = body;

  // Enterprise security: Validate service authentication
  if (!service) {
    await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'MISSING_SERVICE_IDENTIFIER');
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Service identifier required' })
    };
  }

  try {
    const expectedSecret = await getServiceSecret(service);
    
    // Bank-grade security: Constant-time comparison to prevent timing attacks
    if (!appSecret || appSecret.length !== expectedSecret.length) {
      await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'INVALID_APP_SECRET', null, service);
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Invalid app credentials' })
      };
    }
    
    let isValid = true;
    for (let i = 0; i < expectedSecret.length; i++) {
      if (appSecret.charCodeAt(i) !== expectedSecret.charCodeAt(i)) {
        isValid = false;
      }
    }
    
    if (!isValid) {
      await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'INVALID_APP_SECRET', null, service);
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Invalid app credentials' })
      };
    }
  } catch (error) {
    await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'SECRET_RETRIEVAL_FAILED', null, service);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Authentication service unavailable' })
    };
  }

  if (!sessionId) {
    await logAuditEvent('SESSION_VALIDATION_FAILED', null, sourceIp, userAgent, 'MISSING_SESSION_ID', null, service);
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Session ID required' })
    };
  }

  // Validate session (same logic as scan validator)
  const result = await dynamodb.send(new GetItemCommand({
    TableName: MFA_SESSIONS_TABLE,
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

  // Bank-grade session format handling with enhanced security metadata
  let expiry, email, role = 'user', parentSession = null;
  if (result.Item.expiry) {
    expiry = parseInt(result.Item.expiry.N);
    email = result.Item.email.S;
    role = result.Item.role?.S || 'user';
  } else if (result.Item.expiresAt) {
    expiry = parseInt(result.Item.expiresAt.N) * 1000;
    email = result.Item.userId.S;
    role = result.Item.userRole?.S || 'user';
    parentSession = result.Item.parentSession?.S;
    
    // Bank-grade security: IP validation for service sessions
    if (result.Item.sourceIp && result.Item.sourceIp.S !== sourceIp) {
      await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'IP_MISMATCH_DETECTED', email, service);
      return {
        statusCode: 401,
        headers: corsHeaders,
        body: JSON.stringify({ error: 'Session security violation' })
      };
    }
  } else {
    await logAuditEvent('SESSION_VALIDATION_FAILED', sessionId, sourceIp, userAgent, 'INVALID_SESSION_FORMAT', null, service);
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

  // Bank-grade audit logging with PII protection
  const maskedEmail = email.replace(/(.{2}).*@/, '$1***@');
  await logAuditEvent('SESSION_VALIDATION_SUCCESS', sessionId, sourceIp, userAgent, 
    `${service.toUpperCase()}_ACCESS_VALIDATED_FOR_${role.toUpperCase()}`, maskedEmail, service);
  
  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({
      valid: true,
      email: email,
      role: role,
      sessionId: sessionId,
      timeRemaining: expiry - Date.now(),
      needsWarning: false,
      service: service,
      parentSession: parentSession
    })
  };
}

// Bank-grade service authorization with RBAC and comprehensive audit
async function handleServiceSessionGeneration(event, sourceIp, userAgent, corsHeaders) {
  const { sessionId, service } = event.queryStringParameters || {};

  if (!sessionId || !service) {
    await logAuditEvent('ACCESS_DENIED', sessionId, sourceIp, userAgent, 'MISSING_PARAMETERS', null, service);
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Session ID and service required' })
    };
  }

  // Validate dashboard session
  const dashboardSession = await dynamodb.send(new GetItemCommand({
    TableName: MFA_SESSIONS_TABLE,
    Key: { sessionId: { S: sessionId } }
  }));

  if (!dashboardSession.Item) {
    await logAuditEvent('ACCESS_DENIED', sessionId, sourceIp, userAgent, 'INVALID_SESSION', null, service);
    return {
      statusCode: 302,
      headers: { Location: 'https://auth.syml.ai/login' }
    };
  }

  // Check session expiry
  const expiry = parseInt(dashboardSession.Item.expiry.N);
  if (Date.now() > expiry) {
    await logAuditEvent('ACCESS_DENIED', sessionId, sourceIp, userAgent, 'SESSION_EXPIRED', null, service);
    return {
      statusCode: 302,
      headers: { Location: 'https://auth.syml.ai/login' }
    };
  }

  const userId = dashboardSession.Item.email.S;
  const userRole = dashboardSession.Item.role?.S || 'user';
  
  // Bank-grade Role-Based Access Control (RBAC)
  const servicePermissions = {
    'scan': ['admin', 'user'], // All authenticated users can access scan
    'lms': ['admin'], // Only admins can access LMS
    'crm': ['admin']  // Only admins can access CRM
  };
  
  const allowedRoles = servicePermissions[service] || [];
  if (!allowedRoles.includes(userRole)) {
    await logAuditEvent('ACCESS_DENIED', sessionId, sourceIp, userAgent, `INSUFFICIENT_PRIVILEGES_${userRole.toUpperCase()}_ATTEMPTED_${service.toUpperCase()}`, userId, service);
    return {
      statusCode: 403,
      headers: corsHeaders,
      body: JSON.stringify({ 
        error: 'Access denied', 
        message: `Your role (${userRole}) does not have permission to access ${service.toUpperCase()}` 
      })
    };
  }
  
  // Create service session with enhanced security metadata
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + 60 * 60; // 1 hour
  const serviceSessionId = randomUUID();

  await dynamodb.send(new PutItemCommand({
    TableName: MFA_SESSIONS_TABLE,
    Item: {
      sessionId: { S: serviceSessionId },
      userId: { S: userId },
      userRole: { S: userRole },
      appName: { S: `${service}-app` },
      createdAt: { N: String(now) },
      expiresAt: { N: String(expiresAt) },
      sourceIp: { S: sourceIp },
      userAgent: { S: userAgent.substring(0, 500) },
      parentSession: { S: sessionId } // Track session hierarchy
    }
  }));

  // Service URLs
  const serviceUrls = {
    'scan': 'https://statements.syml.ai',
    'lms': 'https://lms.syml.ai',
    'crm': 'https://lms.syml.ai'
  };

  const baseUrl = serviceUrls[service] || 'https://syml.ai';
  const redirectUrl = `${baseUrl}?sessionId=${encodeURIComponent(serviceSessionId)}`;

  // Comprehensive audit logging for bank compliance
  await logAuditEvent('SERVICE_ACCESS_GRANTED', serviceSessionId, sourceIp, userAgent, 
    `${service.toUpperCase()}_ACCESS_AUTHORIZED_FOR_${userRole.toUpperCase()}`, userId, service);

  return {
    statusCode: 302,
    headers: {
      Location: redirectUrl,
      'Cache-Control': 'no-cache, no-store, must-revalidate'
    }
  };
}

// Handle session refresh (heartbeat)
async function handleSessionRefresh(event, sourceIp, userAgent, corsHeaders) {
  const body = JSON.parse(event.body || '{}');
  const { sessionId } = body;

  if (!sessionId) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Session ID required' })
    };
  }

  const validation = await validateAndRefreshSession(sessionId, sourceIp, userAgent);
  
  return {
    statusCode: validation.valid ? 200 : 401,
    headers: corsHeaders,
    body: JSON.stringify({
      valid: validation.valid,
      timeRemaining: validation.timeRemaining,
      needsWarning: validation.needsWarning,
      error: validation.error
    })
  };
}

// Handle comprehensive login functionality
async function handleLogin(event, sourceIp, userAgent, corsHeaders) {
  const method = event.httpMethod || event.requestContext?.httpMethod;
  
  if (method === "GET") {
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

// Handle MFA Setup
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

// Handle Dashboard Router
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

    const redirectUrl = `https://auth.syml.ai/customer?sessionId=${sessionId}`;

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

// Handle service secret retrieval for enterprise authentication
async function handleGetServiceSecret(event, sourceIp, userAgent, corsHeaders) {
  const { service } = event.queryStringParameters || {};
  
  if (!service) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Service parameter required' })
    };
  }
  
  try {
    const appSecret = await getServiceSecret(service);
    await logAuditEvent('SERVICE_SECRET_RETRIEVED', null, sourceIp, userAgent, 'SECRET_PROVIDED', null, service);
    
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({ appSecret })
    };
  } catch (error) {
    await logAuditEvent('SERVICE_SECRET_FAILED', null, sourceIp, userAgent, 'SECRET_RETRIEVAL_ERROR', null, service);
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: 'Secret retrieval failed' })
    };
  }
}

// Handle logout
async function handleLogout(event, sourceIp, userAgent, corsHeaders) {
  const body = JSON.parse(event.body || '{}');
  const { sessionId } = body;

  if (sessionId) {
    // Expire the session immediately
    try {
      await dynamodb.send(new UpdateItemCommand({
        TableName: MFA_SESSIONS_TABLE,
        Key: { sessionId: { S: sessionId } },
        UpdateExpression: 'SET expiry = :expiry',
        ExpressionAttributeValues: {
          ':expiry': { N: '0' }
        }
      }));

      await logAuditEvent('USER_LOGOUT', sessionId, sourceIp, userAgent, 'SESSION_TERMINATED');
    } catch (err) {
      console.error('Logout failed:', err);
    }
  }

  return {
    statusCode: 200,
    headers: {
      ...corsHeaders,
      'Set-Cookie': 'syml_session=; Domain=.syml.ai; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
    },
    body: JSON.stringify({ success: true })
  };
}