import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import * as oidc from 'openid-client';

// Local learning environment only.
const baseUrl = 'http://localhost:3000';
const cookieName = 'iam_lab_session';
const adminGroup = 'IAM-Lab-Admins';

const allowedGroups = new Set([
  'IAM-Lab-Users',
  adminGroup,
]);

for (const key of [
  'OKTA_ISSUER',
  'OKTA_CLIENT_ID',
  'OKTA_CLIENT_SECRET',
  'SESSION_SECRET',
]) {
  if (!process.env[key] || process.env[key].startsWith('replace_')) {
    throw new Error(`Configure ${key} in .env.`);
  }
}

if (process.env.APP_BASE_URL !== baseUrl) {
  throw new Error(`APP_BASE_URL must be ${baseUrl} for this local lab.`);
}

if (process.env.SESSION_SECRET.length < 32) {
  throw new Error('SESSION_SECRET must contain at least 32 characters.');
}

const issuer = new URL(process.env.OKTA_ISSUER);

if (issuer.protocol !== 'https:') {
  throw new Error('The Okta issuer must use HTTPS.');
}

const config = await oidc.discovery(
  issuer,
  process.env.OKTA_CLIENT_ID,
  process.env.OKTA_CLIENT_SECRET,
  oidc.ClientSecretBasic(process.env.OKTA_CLIENT_SECRET),
);

if (!config.serverMetadata().end_session_endpoint) {
  throw new Error('Issuer discovery did not provide a logout endpoint.');
}

const logoutOrigin = new URL(
  config.serverMetadata().end_session_endpoint,
).origin;

const app = express();
app.disable('x-powered-by');

app.use(express.urlencoded({
  extended: false,
  limit: '2kb',
}));

const cookieOptions = {
  httpOnly: true,
  sameSite: 'lax',
  secure: false, // Local HTTP only. HTTPS deployments must use true.
  path: '/',
};

app.use(session({
  name: cookieName,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    ...cookieOptions,
    maxAge: 30 * 60 * 1000,
  },
  // Default MemoryStore is for local testing, not production.
}));

app.use((req, res, next) => {
  res.set({
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy':
      `default-src 'none'; form-action 'self' ${logoutOrigin}; frame-ancestors 'none'; base-uri 'none'`,
  });

  next();
});

const randomValue = () => randomBytes(32).toString('hex');

function matches(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') {
    return false;
  }

  const a = Buffer.from(actual);
  const b = Buffer.from(expected);

  return a.length === b.length && timingSafeEqual(a, b);
}

function sessionAction(req, action) {
  return new Promise((resolve, reject) => {
    req.session[action]((error) => {
      if (error) {
        reject(error);
      } else {
        resolve();
      }
    });
  });
}

function page(content) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Identity Security Lab</title>
</head>
<body>
  <h1>Identity Security Lab</h1>
  ${content}
</body>
</html>`;
}

function requireGroup(groupName) {
  return (req, res, next) => {
    const user = req.session.user;

    if (!user) {
      return res.status(401).json({
        error: 'unauthenticated',
        message: 'Sign in before accessing this resource.',
      });
    }

    // Exact membership check using server-side session data.
    if (!Array.isArray(user.groups) || !user.groups.includes(groupName)) {
      return res.status(403).json({
        error: 'forbidden',
        message: 'Your account does not have access to this resource.',
      });
    }

    next();
  };
}

app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.send(page(`
      <p>You are not signed in.</p>
      <p><a href="/login">Sign in with Okta</a></p>
      <p><a href="/profile">View protected profile</a></p>
      <p><a href="/admin">Test admin access</a></p>
    `));
  }

  // Show the admin link to everyone so authorization can be tested.
  // Access is enforced by the server, not by hiding the link.
  res.send(page(`
    <p>You have an authenticated application session.</p>
    <p><a href="/profile">View protected profile</a></p>
    <p><a href="/admin">Test admin access</a></p>
    <form method="post" action="/logout">
      <input type="hidden" name="csrf" value="${req.session.csrf}">
      <button type="submit">Sign out of this app and Okta</button>
    </form>
  `));
});

app.get('/login', async (req, res, next) => {
  try {
    const login = {
      verifier: oidc.randomPKCECodeVerifier(),
      state: oidc.randomState(),
      nonce: oidc.randomNonce(),
      createdAt: Date.now(),
    };

    req.session.login = login;

    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: `${baseUrl}/authorization-code/callback`,
      response_type: 'code',
      scope: 'openid profile email',
      code_challenge: await oidc.calculatePKCECodeChallenge(login.verifier),
      code_challenge_method: 'S256',
      state: login.state,
      nonce: login.nonce,
      // lab_groups is configured as an app-level custom ID-token claim.
      // No prompt=login: allow normal Okta session behavior.
    });

    await sessionAction(req, 'save');
    res.redirect(url.href);
  } catch (error) {
    next(error);
  }
});

app.get('/authorization-code/callback', async (req, res, next) => {
  try {
    const login = req.session.login;
    delete req.session.login;

    // Consume this login attempt.
    await sessionAction(req, 'save');

    if (!login || Date.now() - login.createdAt > 10 * 60 * 1000) {
      return res.status(400).send(
        'Login expired. Return to / and try again.',
      );
    }

    // Validate the OIDC response with state, nonce, and PKCE.
    const tokens = await oidc.authorizationCodeGrant(
      config,
      new URL(req.originalUrl, baseUrl),
      {
        pkceCodeVerifier: login.verifier,
        expectedState: login.state,
        expectedNonce: login.nonce,
        idTokenExpected: true,
      },
    );

    const claims = tokens.claims();

    if (!claims?.sub || !tokens.id_token) {
      throw new Error('Missing authenticated identity.');
    }

    // Missing or malformed group claims grant no group permissions.
    const groups = Array.isArray(claims.lab_groups) &&
      claims.lab_groups.every((group) => typeof group === 'string')
        ? [...new Set(
            claims.lab_groups.filter((group) => allowedGroups.has(group)),
          )]
        : [];

    // Prevent session fixation after successful authentication.
    await sessionAction(req, 'regenerate');

    req.session.user = {
      subject: claims.sub,
      name: claims.name,
      email: claims.email,
      username: claims.preferred_username,
      groups,
    };

    // ID token stays server-side and is used only as the logout hint.
    req.session.idToken = tokens.id_token;
    req.session.csrf = randomValue();

    await sessionAction(req, 'save');
    res.redirect('/profile');
  } catch (error) {
    next(error);
  }
});

app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send(
      'Not signed in. Open / to start login.',
    );
  }

  res.json({
    message: 'Successfully authenticated with Okta!',
    user: req.session.user,
  });
});

// Evaluate group authorization on every request to this route.
app.get('/admin', requireGroup(adminGroup), (req, res) => {
  res.json({
    message: 'Admin access granted.',
    requiredGroup: adminGroup,
    user: {
      name: req.session.user.name,
    },
  });
});

// Logout requires POST and a matching session-bound CSRF value.
app.post('/logout', async (req, res, next) => {
  try {
    if (!matches(req.body?.csrf, req.session.csrf)) {
      return res.status(403).send('Invalid logout request.');
    }

    const idToken = req.session.idToken;
    const state = randomValue();

    // Remove the authenticated session before redirecting to Okta.
    await sessionAction(req, 'regenerate');

    if (!idToken) {
      await sessionAction(req, 'destroy');
      res.clearCookie(cookieName, cookieOptions);

      return res.send(page(
        '<p>Local session ended. Okta logout was not confirmed.</p>',
      ));
    }

    // Keep only short-lived logout correlation data.
    req.session.logout = {
      state,
      createdAt: Date.now(),
    };

    req.session.cookie.maxAge = 5 * 60 * 1000;
    await sessionAction(req, 'save');

    const url = oidc.buildEndSessionUrl(config, {
      id_token_hint: idToken,
      post_logout_redirect_uri: `${baseUrl}/logout/callback`,
      state,
    });

    // Navigate the browser so Okta can end its browser session.
    res.redirect(303, url.href);
  } catch (error) {
    next(error);
  }
});

app.get('/logout/callback', async (req, res, next) => {
  try {
    const pending = req.session.logout;

    const valid = pending &&
      Date.now() - pending.createdAt < 5 * 60 * 1000 &&
      matches(req.query.state, pending.state);

    if (!valid) {
      return res.status(400).send(
        'Invalid or expired logout callback.',
      );
    }

    await sessionAction(req, 'destroy');
    res.clearCookie(cookieName, cookieOptions);

    res.send(page(`
      <p>Local session ended and Okta logout callback validated.</p>
      <p><a href="/profile">Test protected profile</a></p>
      <p><a href="/admin">Test admin access</a></p>
      <p><a href="/">Return home</a></p>
    `));
  } catch (error) {
    next(error);
  }
});

app.use((error, req, res, next) => {
  // Never log complete errors, request URLs, tokens, or credentials.
  console.error('Request failed:', error.code || error.name);
  res.status(500).send(
    'Request failed. Check the terminal error code.',
  );
});

app.listen(3000, 'localhost', () => {
  console.log(`IAM lab running at ${baseUrl}`);
});