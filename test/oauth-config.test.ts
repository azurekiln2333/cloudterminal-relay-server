// Pure parsing tests: no network, no database.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { loadOauthConfig } from '../src/oauth/config.ts';

describe('oauth config', () => {
  it('is disabled when no OAUTH_* variable is present', () => {
    const result = loadOauthConfig({});
    assert.equal(result.state, 'disabled');
    assert.equal(result.config, null);
    assert.match(result.message, /OAUTH_/);
  });

  it('is degraded when required variables are missing', () => {
    const result = loadOauthConfig({ OAUTH_ISSUER: 'https://sso.test' });
    assert.equal(result.state, 'degraded');
    assert.equal(result.config, null);
    assert.match(result.message, /OAUTH_CLIENT_ID/);
  });

  it('degrades when the issuer is blank', () => {
    const result = loadOauthConfig({ OAUTH_ISSUER: '   ', OAUTH_CLIENT_ID: 'relay' });
    assert.equal(result.state, 'degraded');
    assert.match(result.message, /OAUTH_ISSUER/);
  });

  it('is ready with defaults when the minimum is set', () => {
    const result = loadOauthConfig({ OAUTH_ISSUER: 'https://sso.test', OAUTH_CLIENT_ID: 'relay' });
    assert.equal(result.state, 'ready');
    if (result.state !== 'ready') return;
    assert.equal(result.config.issuer, 'https://sso.test');
    assert.equal(result.config.audience, 'relay');
    assert.equal(result.config.verify, 'jwks');
    assert.equal(result.config.redirectUri, 'cloudterminal://oauth/callback');
    assert.equal(result.config.scopes, 'openid profile');
    assert.equal(result.config.jwksTtlMs, 3_600_000);
    assert.equal(result.config.introspectCacheMs, 60_000);
  });

  it('normalises a trailing slash off the issuer', () => {
    const result = loadOauthConfig({ OAUTH_ISSUER: 'https://sso.test/', OAUTH_CLIENT_ID: 'relay' });
    assert.equal(result.state, 'ready');
    if (result.state === 'ready') assert.equal(result.config.issuer, 'https://sso.test');
  });

  it('keeps the client secret out of the state/message', () => {
    const result = loadOauthConfig({
      OAUTH_ISSUER: 'https://sso.test',
      OAUTH_CLIENT_ID: 'relay',
      OAUTH_CLIENT_SECRET: 'super-secret',
    });
    assert.equal(result.state, 'ready');
    assert.doesNotMatch(result.message, /super-secret/);
    if (result.state === 'ready') assert.equal(result.config.clientSecret, 'super-secret');
  });

  it('rejects a non-URL issuer', () => {
    assert.throws(
      () => loadOauthConfig({ OAUTH_ISSUER: 'not-a-url', OAUTH_CLIENT_ID: 'relay' }),
      /OAUTH_ISSUER/,
    );
  });

  it('rejects a non-http(s) issuer scheme', () => {
    assert.throws(
      () => loadOauthConfig({ OAUTH_ISSUER: 'ftp://sso.test', OAUTH_CLIENT_ID: 'relay' }),
      /http/,
    );
  });

  it('rejects an unknown verify strategy', () => {
    assert.throws(
      () => loadOauthConfig({ OAUTH_ISSUER: 'https://sso.test', OAUTH_CLIENT_ID: 'relay', OAUTH_VERIFY: 'magic' }),
      /OAUTH_VERIFY/,
    );
  });

  it('rejects non-integer and out-of-range timeouts', () => {
    const base = { OAUTH_ISSUER: 'https://sso.test', OAUTH_CLIENT_ID: 'relay' };
    assert.throws(() => loadOauthConfig({ ...base, OAUTH_JWKS_TTL_MS: 'soon' }), /OAUTH_JWKS_TTL_MS/);
    assert.throws(() => loadOauthConfig({ ...base, OAUTH_JWKS_TTL_MS: '10' }), /between 1000 and 86400000/);
    assert.throws(() => loadOauthConfig({ ...base, OAUTH_INTROSPECT_CACHE_MS: '-1' }), /OAUTH_INTROSPECT_CACHE_MS/);
  });

  it('honours an explicit audience and scopes', () => {
    const result = loadOauthConfig({
      OAUTH_ISSUER: 'https://sso.test',
      OAUTH_CLIENT_ID: 'relay',
      OAUTH_AUDIENCE: 'api',
      OAUTH_SCOPES: 'openid profile email',
    });
    assert.equal(result.state, 'ready');
    if (result.state === 'ready') {
      assert.equal(result.config.audience, 'api');
      assert.equal(result.config.scopes, 'openid profile email');
    }
  });
});
