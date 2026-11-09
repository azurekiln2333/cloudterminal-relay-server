// Deployment contract for the container image.
//
// These checks are deliberately static and dependency-free: they must run on a
// machine with nothing installed, and they must fail when someone reintroduces
// source builds, source mounts or a broken COPY list into the deployment path.
//
// What is asserted:
//   1. the default Compose entries pull an image and never build or mount source
//   2. a local build exists only as an explicitly named override
//   3. the image ships exactly the relay import graph (no missing COPY)
//   4. the image never carries desktop-agent dependencies
//   5. the image stays unprivileged with a health endpoint and a persistent key
//   6. CI publishes images only where credentials are legitimate, and never
//      points `latest` at a pre-release
//   7. the docs never claim an image exists before one has been published
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { test } from 'node:test';

// `test/` sits directly under the repository root: this repository *is* the
// relay server, so the deployment files and the CI configuration are siblings
// of `test/` rather than one level up.
const serverDir = path.resolve(import.meta.dirname, '..');
const repoDir = serverDir;

const read = (relative: string) => readFile(path.join(serverDir, relative), 'utf8');
const readRepo = (relative: string) => readFile(path.join(repoDir, relative), 'utf8');

/** Directories the runtime image copies; anything else must not be imported. */
const COPIED_DIRS = ['src/shared', 'src/relay', 'src/db', 'src/oauth'];

/** Compose service blocks keyed by service name, without a YAML parser. */
function serviceBlock(compose: string, service: string): string {
  const lines = compose.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trimEnd() === `  ${service}:`);
  assert.notEqual(start, -1, `missing service ${service}`);
  const block: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (/^\S/.test(line) || /^ {2}\S/.test(line)) break;
    block.push(line);
  }
  return block.join('\n');
}

/** A nested mapping (for example `volumes:`) inside a service block. */
function nested(block: string, key: string): string[] {
  const lines = block.split(/\r?\n/);
  const start = lines.findIndex((line) => line.trimEnd() === `    ${key}:`);
  if (start === -1) return [];
  const entries: string[] = [];
  for (const line of lines.slice(start + 1)) {
    if (!/^ {6}/.test(line)) break;
    if (line.trimStart().startsWith('#')) continue;
    entries.push(line.trim().replace(/^-\s*/, ''));
  }
  return entries;
}

/** Configuration lines only; comments are documentation, not behaviour. */
function withoutComments(text: string): string {
  return text
    .split(/\r?\n/)
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n');
}

/** One event block of the CNB config (`main.push`, `"v*".tag_push`, ...). */
function cnbEvent(cnb: string, topLevel: string, event: string): string {
  const top = topLevel === 'main' ? cnb.slice(0, cnb.indexOf('"v*":')) : cnb.slice(cnb.indexOf('"v*":'));
  const marker = `\n  ${event}:`;
  const start = top.indexOf(marker);
  assert.notEqual(start, -1, `cnb config must define ${topLevel}.${event}`);
  const rest = top.slice(start + 1);
  const nextEvent = /\n {2}[a-z_]+:/.exec(rest.slice(1));
  return nextEvent ? rest.slice(0, nextEvent.index + 1) : rest;
}

const PUBLISHING_EVENTS: Array<[string, string]> = [
  ['main', 'push'],
  ['"v*"', 'tag_push'],
];
const VERIFY_ONLY_EVENTS: Array<[string, string]> = [
  ['main', 'pull_request'],
  ['main', 'api_trigger'],
];

/** Top-level `name` for a Compose file. */
function projectName(compose: string): string | undefined {
  return compose.match(/^name:\s*(\S+)\s*$/m)?.[1];
}

test('default compose entries pull an image and never build on the server', async () => {
  for (const file of ['compose.yml', 'compose.tls.yml']) {
    const compose = await read(file);
    const relay = serviceBlock(compose, 'relay');

    assert.equal(projectName(compose), 'cloudterminal', `${file} must keep the cloudterminal project name`);
    assert.match(relay, /^ {4}image: "\$\{RELAY_IMAGE:-[^}]+\}"$/m, `${file} must pull a configurable image`);
    assert.doesNotMatch(compose, /^ {4}build:/m, `${file} must not build in the default deployment`);
    assert.doesNotMatch(compose, /dockerfile:/, `${file} must not reference a Dockerfile`);
    assert.doesNotMatch(relay, /compose\.build\.yml/, `${file} must not depend on the build override`);
    // No source may be mounted from the host; only named volumes for state.
    const mounted = nested(relay, 'volumes');
    assert.ok(mounted.length > 0, `${file} must mount the relay state volume`);
    for (const volume of mounted) {
      assert.match(volume, /^[a-z-]+:\/data$/, `${file} may only mount the state volume, saw ${volume}`);
    }
    assert.match(relay, /^ {4}restart: unless-stopped$/m, `${file} must restart the relay`);
    assert.match(relay, /^ {4}init: true$/m, `${file} must run with an init process`);
    // `compose` is the raw file text, so it may arrive with CRLF line endings
    // (a Windows checkout). Anchor with `\r?\n` rather than a literal `\n`.
    assert.match(compose, /^volumes:\r?\n {2}relay-data:$/m, `${file} must keep the persistent key volume`);
  }

  const lan = await read('compose.yml');
  assert.match(serviceBlock(lan, 'relay'), /"\$\{RELAY_PORT:-8787\}:8787"/, 'LAN entry must publish RELAY_PORT');

  const tls = await read('compose.tls.yml');
  const relay = serviceBlock(tls, 'relay');
  assert.match(relay, /RELAY_TRUST_PROXY: "1"/, 'TLS entry must trust the proxy headers');
  assert.doesNotMatch(relay, /ports:/, 'TLS entry must not publish the relay port');
  const published = [...tls.matchAll(/^ {6}- "([0-9]+):[0-9]+"$/gm)].map((match) => match[1]);
  assert.deepEqual(published.sort(), ['443', '80'], 'TLS entry must publish only TCP 80 and 443');
  assert.match(tls, /condition: service_healthy/, 'Caddy must wait for a healthy relay');
  assert.match(tls, /RELAY_DOMAIN: "\$\{RELAY_DOMAIN:\?/, 'TLS entry must require RELAY_DOMAIN');
});

test('local build stays an explicitly named override', async () => {
  const build = await read('compose.build.yml');
  assert.match(build, /^ {4}build:$/m, 'build override must declare a build section');
  assert.match(build, /^ {6}context: \.$/m, 'build context must be the server directory');
  assert.match(build, /^ {6}dockerfile: Dockerfile$/m, 'build override must name the Dockerfile');
  assert.match(build, /pull_policy: build/, 'build override must force a local build');

  const readme = await read('README.md');
  const buildCommands = readme.split(/\r?\n/).filter((line) => line.includes('--build'));
  assert.ok(buildCommands.length > 0, 'README must document the local build path');
  for (const line of buildCommands) {
    assert.match(line, /compose\.build\.yml/, `every --build command must name the override: ${line.trim()}`);
  }
  const tunnel = await read('TUNNEL.md');
  for (const line of tunnel.split(/\r?\n/).filter((entry) => entry.includes('--build'))) {
    assert.match(line, /compose\.build\.yml/, `every --build command must name the override: ${line.trim()}`);
  }
});

test('image copies exactly the trees the relay imports', async () => {
  const dockerfile = await read('Dockerfile');
  const copied = [...dockerfile.matchAll(/^COPY (src\/[a-z]+) \.\/src\/[a-z]+$/gm)].map((match) => match[1]);
  assert.deepEqual([...copied].sort(), [...COPIED_DIRS].sort(), 'Dockerfile must copy exactly the relay source trees');

  // Walk the real import graph so a new cross-directory import fails here
  // instead of failing at container start.
  const seen = new Set<string>();
  const queue = [path.join(serverDir, 'src/relay/main.ts')];
  while (queue.length > 0) {
    const file = queue.pop()!;
    if (seen.has(file)) continue;
    seen.add(file);
    const source = await readFile(file, 'utf8');
    for (const match of source.matchAll(/(?:from|import)\s+['"](\.[^'"]+)['"]/g)) {
      const specifier = match[1] ?? '';
      const resolved = path.resolve(path.dirname(file), specifier);
      assert.ok(
        COPIED_DIRS.some((dir) => resolved.startsWith(path.join(serverDir, dir) + path.sep)),
        `${path.relative(serverDir, file)} imports ${specifier}, which the image does not copy`,
      );
      queue.push(resolved);
    }
  }
  assert.ok(seen.size > 10, `import walk found only ${seen.size} files; expected the relay source graph`);

  const dockerignore = await read('.dockerignore');
  for (const dir of COPIED_DIRS) {
    const escaped = dir.replace('/', '\\/');
    assert.match(dockerignore, new RegExp(`!${escaped}/\\*\\*`), `.dockerignore must allow ${dir}`);
  }
  assert.match(dockerignore, /!deploy\/relay\/package-lock\.json/, '.dockerignore must allow the locked relay deps');
});

test('image never carries desktop agent dependencies', async () => {
  const runtime = JSON.parse(await read('deploy/relay/package.json')) as { dependencies: Record<string, string> };
  assert.deepEqual(Object.keys(runtime.dependencies).sort(), ['mysql2', 'ws'], 'relay runtime must stay mysql2 + ws');

  const lock = JSON.parse(await read('deploy/relay/package-lock.json')) as { packages: Record<string, unknown> };
  for (const banned of ['node-pty', '@anthropic-ai/claude-agent-sdk']) {
    assert.equal(
      Object.keys(lock.packages).some((entry) => entry.includes(banned)),
      false,
      `relay lock file must not contain ${banned}`,
    );
  }

  const dockerfile = await read('Dockerfile');
  assert.doesNotMatch(dockerfile, /node-pty|claude-agent-sdk/, 'image must not install desktop dependencies');
  assert.doesNotMatch(dockerfile, /COPY \. \./, 'image must not copy the whole server directory');
  assert.match(dockerfile, /npm ci --omit=dev --ignore-scripts/, 'image must install only locked production deps');
});

test('image stays unprivileged with a health endpoint and a persistent key', async () => {
  const dockerfile = await read('Dockerfile');
  assert.match(dockerfile, /^USER node$/m, 'image must run as the non-root node user');
  assert.match(dockerfile, /chown node:node \/data/, 'image must make /data writable for the node user');
  assert.match(dockerfile, /RELAY_KEY_FILE=\/data\/relay-key/, 'image must persist the key in /data');
  assert.match(dockerfile, /HEALTHCHECK[^\n]*\n?[^\n]*\/healthz/, 'image must health-check /healthz');
  assert.match(dockerfile, /EXPOSE 8787/, 'image must declare the relay port');
  assert.match(dockerfile, /CMD \["node", "src\/relay\/main\.ts"\]/, 'image must start the relay');
});

test('github workflow builds on pull requests without credentials and gates latest', async () => {
  const workflow = await readRepo('.github/workflows/image.yml');

  assert.match(workflow, /^ {2}pull_request:$/m, 'workflow must run on pull requests');
  assert.match(workflow, /^ {4}needs: \[deployment-files\]$/m, 'release must depend on the static check');
  assert.match(workflow, /push: false/, 'the build step must not push directly');
  assert.match(workflow, /load: true/, 'the built image must be loaded for smoke tests');

  // The login and push steps must both be gated on the resolved policy, so a
  // pull request never receives a credential and never publishes.
  for (const name of ['Log in to the registry', 'Push the smoke-tested image']) {
    const start = workflow.indexOf(`- name: ${name}`);
    assert.ok(start > 0, `workflow must contain the ${name} step`);
    const rest = workflow.slice(start);
    const end = rest.indexOf('\n      - name:', 1);
    const step = end === -1 ? rest : rest.slice(0, end);
    assert.match(step, /if: steps\.meta\.outputs\.push == 'true'/, `${name} must be skipped when the run does not push`);
  }

  // The smoke test must run before the push step, or a broken image ships.
  assert.ok(
    workflow.indexOf('- name: Smoke-test the built image') < workflow.indexOf('- name: Push the smoke-tested image'),
    'the image must be smoke-tested before it is pushed',
  );
  const smoke = workflow.slice(
    workflow.indexOf('- name: Smoke-test the built image'),
    workflow.indexOf('- name: Log in to the registry'),
  );
  for (const marker of ['healthz', 'id -un', '/data/relay-key', 'hello_ok', 'show-key.ts']) {
    assert.ok(smoke.includes(marker), `github smoke test must verify ${marker}`);
  }
  assert.doesNotMatch(workflow, /console\.log\('image ok'\)/, 'the smoke test must not be a version echo');

  // A dispatch input must arrive through env, not be interpolated into shell text.
  assert.doesNotMatch(workflow, /tags\+=\('"'"'\$\{\{ inputs\.tag/, 'dispatch tag must not be interpolated into shell');
  assert.match(workflow, /DISPATCH_TAG: \$\{\{ inputs\.tag \}\}/, 'dispatch tag must be passed through env');
  assert.match(workflow, /\^\[A-Za-z0-9_\]\[A-Za-z0-9\._-\]\{0,127\}\$/, 'dispatch tag must be validated as a Docker tag');

  // `latest` may only be added on a stable release tag.
  const meta = workflow.slice(workflow.indexOf('Resolve image reference and tags'), workflow.indexOf('setup-buildx'));
  assert.match(meta, /push=false/, 'pull requests must resolve to a non-pushing run');
  assert.match(meta, /\*-\*\)/, 'pre-release tags must be detected');
  assert.match(meta, /latest tag skipped/, 'pre-release tags must skip the latest tag');
  assert.match(meta, /IMAGE_REPOSITORY/, 'image path must derive from the repository, not be hardcoded');
  assert.doesNotMatch(meta, /ghcr\.io\/[a-z0-9-]+\//, 'image path must not hardcode an owner');
});

test('cnb pipeline never pushes for pull requests and gates latest', async () => {
  const pipeline = await readRepo('.cnb.yml');
  const tagSection = pipeline.indexOf('"v*":');
  assert.ok(tagSection > 0, 'cnb pipeline must define a v* tag trigger');

  // Every event verifies the same way, regardless of whether it publishes.
  // Match the stage declaration, not a bare name: YAML anchors such as
  // `&relay-build-image` also contain `build-image`.
  const stage = (name: string) => `- name: ${name}`;
  for (const [top, event] of [...VERIFY_ONLY_EVENTS, ...PUBLISHING_EVENTS]) {
    const block = cnbEvent(pipeline, top, event);
    const stagesByName = ['static-deployment-check', 'build-image', 'smoke-test-image'];
    const order = stagesByName.map((name) => block.indexOf(stage(name)));
    for (const [index, name] of stagesByName.entries()) {
      assert.ok((order[index] ?? -1) > 0, `${top}.${event} must run the ${name} stage`);
    }
    assert.deepEqual([...order].sort((a, b) => a - b), order, `${top}.${event} must check, build, then smoke`);
    // A version echo is not a relay smoke test.
    assert.doesNotMatch(block, /console\.log\('image ok'\)/, `${top}.${event} must not fake the smoke test`);
  }

  // The smoke stage must prove the relay actually works.
  const smoke = cnbEvent(pipeline, 'main', 'pull_request');
  for (const marker of ['healthz', 'id -un', '/data/relay-key', 'hello_ok', 'show-key.ts']) {
    assert.ok(smoke.includes(marker), `cnb smoke test must verify ${marker}`);
  }
  assert.match(smoke, /refusing to continue/, 'cnb smoke test must refuse to continue an unhealthy image');
  assert.match(smoke, /docker logs/, 'cnb smoke test must print relay logs when it fails');

  // Every event must reuse that one smoke stage rather than re-implement it,
  // so a publishing path cannot silently skip a check. The first event defines
  // the anchor; the rest must alias it.
  for (const [top, event] of [...VERIFY_ONLY_EVENTS, ...PUBLISHING_EVENTS]) {
    const block = cnbEvent(pipeline, top, event);
    const defines = top === 'main' && event === 'pull_request';
    const marker = defines ? 'script: &smoke-image' : 'script: *smoke-image';
    assert.ok(block.includes(marker), `${top}.${event} must ${defines ? 'define' : 'use'} the shared smoke stage`);
    const staticMarker = defines ? 'script: &static-check' : 'script: *static-check';
    assert.ok(block.includes(staticMarker), `${top}.${event} must ${defines ? 'define' : 'use'} the shared static check`);
  }

  // Nothing may be pushed before the smoke test has passed.
  for (const [top, event] of PUBLISHING_EVENTS) {
    const block = cnbEvent(pipeline, top, event);
    const publishAt = block.indexOf(stage('publish-image'));
    assert.ok(publishAt > 0, `${top}.${event} must publish`);
    assert.ok(publishAt > block.indexOf(stage('smoke-test-image')), `${top}.${event} must smoke-test before publishing`);
    assert.ok(publishAt > block.indexOf(stage('static-deployment-check')), `${top}.${event} must check before publishing`);
  }

  // Verification-only events must never publish.
  for (const [top, event] of VERIFY_ONLY_EVENTS) {
    const block = cnbEvent(pipeline, top, event);
    assert.doesNotMatch(block, /docker push/, `${top}.${event} must not push an image`);
    assert.equal(block.indexOf(stage('publish-image')), -1, `${top}.${event} must not publish`);
  }

  const tagPublish = pipeline.slice(tagSection);
  assert.match(tagPublish, /CNB_IMAGE/, 'tag pipeline must allow an explicit image override');
  assert.match(tagPublish, /CNB_BRANCH/, 'tag pipeline must read the tag from CNB_BRANCH');
  assert.match(tagPublish, /v\[0-9\]\*\.\[0-9\]\*\.\[0-9\]\*/, 'tag pipeline must validate the release tag shape');
  assert.match(tagPublish, /\*-\*\)/, 'tag pipeline must detect pre-release tags');
  assert.match(tagPublish, /latest tag skipped/, 'pre-release tags must skip the latest tag');

  assert.match(pipeline, /CNB_DOCKER_REGISTRY/, 'image path must come from the platform registry variable');
  assert.match(pipeline, /CNB_REPO_SLUG_LOWERCASE/, 'image path must come from the repository slug variable');

  // Branch pushes publish a sha tag for testing, never latest.
  const branchPush = cnbEvent(pipeline, 'main', 'push');
  assert.match(branchPush, /sha-\$\{CNB_COMMIT_SHORT\}/, 'branch pushes must tag with the commit sha');
  assert.doesNotMatch(branchPush, /:latest/, 'branch pushes must not publish latest');
});

test('optional account settings actually reach the relay container', async () => {
  for (const file of ['compose.yml', 'compose.tls.yml']) {
    const compose = await read(file);
    const relay = serviceBlock(compose, 'relay');
    // Documented DB_*/OAUTH_* settings live in .env; without env_file they
    // would never reach the process, so the README would be lying.
    assert.match(relay, /^ {4}env_file:$/m, `${file} must forward .env into the relay`);
    assert.match(relay, /^ {6}- path: \.env$/m, `${file} must read the same .env it interpolates`);
    assert.match(relay, /^ {8}required: false$/m, `${file} must keep working without a .env file`);
  }

  // An explicit environment entry must still win over env_file defaults.
  const tls = serviceBlock(await read('compose.tls.yml'), 'relay');
  assert.match(
    tls,
    /^ {4}environment:\r?\n(?: {6}#.*\r?\n)* {6}RELAY_TRUST_PROXY: "1"$/m,
    'TLS entry must pin RELAY_TRUST_PROXY in environment:, which outranks env_file',
  );

  const readme = await read('README.md');
  const section = readme.slice(readme.indexOf('## 7. 可选账号层'));
  assert.match(section, /env_file/, 'README must explain how DB_*/OAUTH_* reach the container');
  assert.match(section, /printenv DB_HOST/, 'README must show how to confirm the settings arrived');
  assert.ok(section.includes('不要'), 'README must warn about RELAY_KEY placement');
  assert.ok(
    section.includes('RELAY_KEY') && section.includes('relay-data'),
    'README must point RELAY_KEY at the relay-data volume instead of .env',
  );

  const envExample = await read('.env.example');
  assert.match(envExample, /env_file/, '.env.example must explain the env_file forwarding');
  assert.match(envExample, /Do not put RELAY_KEY here/, '.env.example must warn against RELAY_KEY');
});

test('docs never claim an unpublished image exists', async () => {
  const readme = await read('README.md');
  assert.match(readme, /当前没有任何已发布的镜像/, 'README must state that no image is published yet');
  assert.match(readme, /首次 CI 发布成功之前/, 'README must explain the image only exists after the first CI run');
  assert.match(readme, /RELAY_IMAGE/, 'README must document the RELAY_IMAGE override');
  assert.match(readme, /docker\.cnb\.cool\/azurekiln\/cloudterminal/, 'README must name the default image path');
  assert.match(readme, /ghcr\.io\/<owner>\/<repo>/, 'README must describe the GitHub image path');
  assert.match(readme, /manifest inspect/, 'README must tell operators how to verify the image exists');

  const envExample = await read('.env.example');
  assert.match(envExample, /WARNING: nothing is published at the default path yet/, '.env.example must warn about the image');
  assert.match(envExample, /^RELAY_IMAGE=/m, '.env.example must expose RELAY_IMAGE');
  assert.match(envExample, /^RELAY_DOMAIN=/m, '.env.example must expose RELAY_DOMAIN');

  const compose = await read('compose.yml');
  assert.match(compose, /exists there yet/, 'compose.yml must not imply the image exists');

  const tunnel = await read('TUNNEL.md');
  assert.match(tunnel, /RELAY_IMAGE/, 'TUNNEL.md must mention the image override');
  for (const line of tunnel.split(/\r?\n/).filter((entry) => entry.includes('--build'))) {
    assert.match(line, /compose\.build\.yml/, `TUNNEL.md must not build by default: ${line.trim()}`);
  }

  // No deployment doc may promise that the relay image is already pullable.
  for (const file of ['README.md', 'TUNNEL.md']) {
    const doc = await read(file);
    assert.doesNotMatch(doc, /镜像(已经|已)发布/, `${file} must not claim the image is already published`);
  }
});

test('repository root stays self-contained for source deployments', async () => {
  const dockerignore = await read('.dockerignore');
  assert.match(dockerignore, /^\*\*$/m, '.dockerignore must exclude everything first');

  const entries = await readdir(serverDir);
  for (const required of ['compose.yml', 'compose.tls.yml', 'compose.build.yml', 'Dockerfile', 'deploy']) {
    assert.ok(entries.includes(required), `the repository root must contain ${required}`);
  }
  // The Caddyfile is the only bind mount left in any entry.
  const tls = await read('compose.tls.yml');
  assert.match(tls, /\.\/deploy\/Caddyfile:\/etc\/caddy\/Caddyfile:ro/, 'Caddy config must resolve inside the repository');
  for (const file of ['compose.yml', 'compose.tls.yml', 'compose.build.yml']) {
    const config = withoutComments(await read(file));
    assert.doesNotMatch(config, /\.\.\//, `${file} must not resolve a path outside the repository`);
  }
  const build = await read('compose.build.yml');
  assert.doesNotMatch(build, /context: \.\./, 'build context must stay inside the repository');
});