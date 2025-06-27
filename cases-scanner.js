#!/usr/bin/env node
'use strict';

/*
 * Case Scanner – high-performance domain & port scanner
 * Modes: HTTP, TLS/SSL, WebSocket
 * Features: proxy support, hard-coded UID lock, concurrency control, JSON/text export
 * UID required: Caseklowzed455
 * License: MIT
 */

const fs = require('fs');
const http = require('http');
const tls = require('tls');
const WebSocket = require('ws');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const cliProgress = require('cli-progress');
const chalk = require('chalk');
const { HttpsProxyAgent } = require('https-proxy-agent');

// ─── CLI PARSING ───────────────────────────────────────────────────────────────
const argv = yargs(hideBin(process.argv))
  .usage('Usage: $0 --uid Caseklowzed455 [options] <host …>')
  .option('ssl', { type: 'boolean', desc: 'TLS/SSL handshake scan' })
  .option('ws',  { type: 'boolean', desc: 'WebSocket upgrade scan' })
  .option('p',   { alias: 'port', type: 'number', desc: 'Port override' })
  .option('x',   { alias: 'proxy', type: 'string', desc: 'HTTP proxy host:port' })
  .option('c',   { alias: 'concurrency', type: 'number', default: 100, desc: 'Parallel sockets' })
  .option('o',   { alias: 'out', type: 'string', desc: 'Write results to file (.json | .txt)' })
  .option('t',   { alias: 'timeout', type: 'number', default: 5000, desc: 'Socket timeout (ms)' })
  .option('l',   { alias: 'list', type: 'string', desc: 'File containing newline-separated targets' })
  .demandOption(['uid'], 'Run with --uid Caseklowzed455')
  .help()
  .argv;

// ─── UID GATE ─────────────────────────────────────────────────────────────────
const REQUIRED_UID = 'Caseklowzed455';
if (argv.uid !== REQUIRED_UID) {
  console.error(chalk.red('❌  Incorrect UID. Supply --uid Caseklowzed455.'));
  process.exit(1);
}

// ─── TARGET COLLECTION ────────────────────────────────────────────────────────
let targets = argv._.map(String);
if (argv.list) {
  try {
    targets = targets.concat(
      fs.readFileSync(argv.list, 'utf8')
        .split(/\r?\n/)
        .filter(Boolean)
    );
  } catch (err) {
    console.error(chalk.red(`Unable to read list file: ${err.message}`));
    process.exit(1);
  }
}
if (!targets.length) {
  console.error(chalk.yellow('No targets supplied. See --help.'));
  process.exit(1);
}

// ─── RUNTIME SETTINGS ─────────────────────────────────────────────────────────
const port   = argv.port || (argv.ssl ? 443 : 80);
const agent  = argv.proxy ? new HttpsProxyAgent('http://' + argv.proxy) : undefined;
const bar    = new cliProgress.SingleBar({
  format: '{bar} {percentage}% | {value}/{total} | {target} | {status}',
  hideCursor: true
});

// ─── STATE ────────────────────────────────────────────────────────────────────
const results = [];
let active = 0;
let idx = 0;

// ─── SCANNERS ─────────────────────────────────────────────────────────────────
function scanHTTP(host) {
  return new Promise(resolve => {
    const req = http.get({ host, port, path: '/', agent, timeout: argv.timeout }, res => {
      res.destroy();
      resolve({ host, port, mode: 'HTTP', ok: true, status: res.statusCode });
    });
    req.on('timeout', () => { req.destroy(); resolve({ host, port, mode: 'HTTP', ok: false, timeout: true }); });
    req.on('error',  () => resolve({ host, port, mode: 'HTTP', ok: false }));
  });
}

function scanTLS(host) {
  return new Promise(resolve => {
    const socket = tls.connect({ host, port, servername: host, agent, rejectUnauthorized: false, timeout: argv.timeout }, () => {
      const cert = socket.getPeerCertificate();
      socket.end();
      resolve({ host, port, mode: 'TLS', ok: true, issuer: cert?.issuer?.O, expires: cert?.valid_to });
    });
    socket.on('timeout', () => { socket.destroy(); resolve({ host, port, mode: 'TLS', ok: false, timeout: true }); });
    socket.on('error',   () => resolve({ host, port, mode: 'TLS', ok: false }));
  });
}

function scanWS(host) {
  return new Promise(resolve => {
    const ws = new WebSocket(`ws://${host}:${port}`, { agent, handshakeTimeout: argv.timeout });
    ws.on('open',  () => { ws.terminate(); resolve({ host, port, mode: 'WS', ok: true }); });
    ws.on('error', () => resolve({ host, port, mode: 'WS', ok: false }));
  });
}

async function runScan(host) {
  if (argv.ws)  return scanWS(host);
  if (argv.ssl) return scanTLS(host);
  return scanHTTP(host);
}

// ─── WORKER LOOP ──────────────────────────────────────────────────────────────
function spawn() {
  while (active < argv.concurrency && idx < targets.length) {
    const host = targets[idx++];
    active++;
    bar.update(bar.value, { target: host, status: '⏳' });
    runScan(host)
      .then(res => finish(host, res))
      .catch(() => finish(host, { host, port, mode: 'ERR', ok: false }));
  }
}

function finish(host, res) {
  results.push(res);
  bar.increment({ target: host, status: res.ok ? chalk.green('✓') : chalk.red('✗') });
  active--;
  if (idx < targets.length) {
    spawn();
  } else if (active === 0) {
    bar.stop();
    outputResults();
  }
}

// ─── OUTPUT ───────────────────────────────────────────────────────────────────
function outputResults() {
  const ok = results.filter(r => r.ok).length;
  console.log(chalk.cyan(`\nFinished: ${ok}/${targets.length} reachable.\n`));

  if (!argv.out) return;

  try {
    if (argv.out.endsWith('.json')) {
      fs.writeFileSync(argv.out, JSON.stringify(results, null, 2));
    } else {
      fs.writeFileSync(
        argv.out,
        results.map(r => `${r.ok ? '✓' : '✗'}\t${r.mode}\t${r.host}:${r.port}`).join('\n')
      );
    }
    console.log(chalk.gray(`Saved to ${argv.out}`));
  } catch (err) {
    console.error(chalk.red(`Cannot write output: ${err.message}`));
  }
}

// ─── KICK-OFF ────────────────────────────────────────────────────────────────
bar.start(targets.length, 0, { target: '', status: '' });
spawn();
