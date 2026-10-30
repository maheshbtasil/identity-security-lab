import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import * as oidc from 'openid-client';

const required = [
  'OKTA_ISSUER',
  'OKTA_CLIENT_ID',
  'OKTA_CLIENT_SECRET',
  'APP_BASE_URL',
  'SESSION_SECRET',
];

for (const name of required) {
  if (!process.env[name] || process.env[name].startsWith('replace_')) {
    throw new Error(`Set ${name} in your .env file first.`);
  }
}

const baseUrl = process.env.APP_BASE_URL;
if (baseUrl !== 'http://localhost:3000') {
  throw new Error('For this lab, APP_BASE_URL must be http://localhost:3000');
}

const config = await oidc.discovery(
  new URL(process.env.OKTA_ISSUER),
  process.env.OKTA_CLIENT_ID,
  process.env.OKTA_CLIENT_SECRET,
  oidc.ClientSecretBasic(process.env.OKTA_CLIENT_SECRET),
);

const app = express();
app.disable('x-powered-by');

app.use(session({
  name: 'iam_lab_session',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false, // Local HTTP lab only.
    maxAge: 30 * 60 * 1000,
  },
}));

app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.get('/', (req, res) => {
  res.send(`
    <h1>Identity Security Lab</h1>
    <p>Okta OIDC authentication demonstration</p>
    <a href="/login">Sign in with Okta</a>
    <p><a href="/profile">View protected profile</a></p>
  `);
});

app.get('/login', async (req, res, next) => {
  try {
    const verifier = oidc.randomPKCECodeVerifier();
    const state = oidc.randomState();
    const nonce = oidc.randomNonce();

    req.session.login = {
      verifier, state, nonce, createdAt: Date.now(),
    };

    const url = oidc.buildAuthorizationUrl(config, {
      redirect_uri: `${baseUrl}/authorization-code/callback`,
      scope: 'openid profile email',
      response_type: 'code',
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
      code_challenge_method: 'S256',
      state,
      nonce,
      prompt: 'login',
    });

    req.session.save((error) => {
      if (error) return next(error);
      res.redirect(url.href);
    });
  } catch (error) {
    next(error);
  }
});

app.get('/authorization-code/callback', async (req, res, next) => {
  try {
    const login = req.session.login;
    delete req.session.login;

    if (!login || Date.now() - login.createdAt > 10 * 60 * 1000) {
      return res.status(400).send('Login expired. Return to / and try again.');
    }

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
    if (!claims?.sub) throw new Error('Missing authenticated user identity.');

    const user = {
      subject: claims.sub,
      name: claims.name,
      email: claims.email,
      username: claims.preferred_username,
    };

    req.session.regenerate((error) => {
      if (error) return next(error);
      req.session.user = user;
      req.session.save((saveError) => {
        if (saveError) return next(saveError);
        res.redirect('/profile');
      });
    });
  } catch (error) {
    next(error);
  }
});

app.get('/profile', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Not signed in. Open / to start login.');
  }

  res.json({
    message: 'Successfully authenticated with Okta!',
    user: req.session.user,
  });
});

app.use(async (error, req, res, next) => {
  console.error('Authentication error:', error.code || error.name);

  const response = error.response;
  console.error('HTTP status:', response?.status ?? 'unavailable');

  if (response && typeof response.clone === 'function') {
    try {
      const body = await response.clone().json();

      console.error('Okta error:', JSON.stringify({
        error: body.error,
        description: body.error_description,
        errorCode: body.errorCode,
        errorSummary: body.errorSummary,
      }, null, 2));
    } catch {
      console.error('Error response body unavailable.');
    }
  }

  res.status(500).send(
    'Authentication failed. Check the terminal error details.',
  );
});

app.listen(3000, 'localhost', () => {
  console.log(`IAM lab running at ${baseUrl}`);
});