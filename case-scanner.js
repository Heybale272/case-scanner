#!/usr/bin/env node /**

High‑performance domain / port scanner

Modes:  plain HTTP, TLS/SSL handshake, WebSocket upgrade

Extra:  proxy support, UID lock, JSON or text export

Author: Gift (ChatGPT) – MIT */


const fs   = require('fs'); const net  = require('net'); const tls  = require('tls'); const http = require('http'); const https= require('https'); const WebSocket = require('ws'); const yargs = require('yargs/yargs'); const { hideBin } = require('yargs/helpers'); const chalk = require('chalk'); const cliProgress = require('cli-progress'); const { HttpsProxyAgent } = require('https-proxy-agent');

// ---------- 1. CLI --------- const argv = yargs(hideBin(process.argv)) .usage('Usage: $0 [options] <domain1> <domain2> … | -l list.txt') .option('ssl', { type:'boolean', desc:'TLS handshake test (default HTTP)' }) .option('ws',  { type:'boolean', desc:'WebSocket handshake test' }) .option('p',   { alias:'port', type:'number', desc:'Port (default 80/443)' }) .option('x',   { alias:'proxy', type:'string', desc:'HTTP(S) proxy (host:port)' }) .option('o',   { alias:'out', type:'string', desc:'Save results to file (json|txt)' }) .option('c',   { alias:'concurrency', type:'number', default:100, desc:'Simultaneous sockets' }) .option('uid', { type:'string', desc:'Required UID token – blocks run if absent' }) .option('l',   { alias:'list', type:'string', desc:'Read targets from file (newline‑separated)' }) .example('$0 google.com github.com',       'Plain HTTP scan, default port 80') .example('$0 --ssl google.com -p 443',     'TLS handshake') .example('$0 --ws chat.example.com',       'WebSocket upgrade test') .example('$0 -l hosts.txt -x 127.0.0.1:8080', 'Scan list through proxy') .demandOption(['uid'], 'You must provide --uid Caseklowzed455') .help() .argv;

// ---------- 2. UID gate (hard‑coded) ---------- const MY_UID = 'Caseklowzed455';                 // ← Your UID is fixed here if (argv.uid !== MY_UID) { console.error(chalk.red('Wrong UID – supply the correct one with --uid Caseklowzed455.')); process.exit(1); }

// ---------- 3. Collect targets ---------- let targets = argv._.map(String); if (argv.list) { try { targets = targets.concat(fs.readFileSync(argv.list,'utf8').split(/\r?\n/).filter(Boolean)); } catch(e) { console.error(chalk.red(Could not read list file: ${e.message})); process.exit(1); } } if (!targets.length) { console.error(chalk.yellow('No targets specified. See --help.')); process.exit(1); }

// pick default port per mode const defaultPort = argv.ssl ? 443 : 80; const port = argv.port || defaultPort;

// proxy agent const agent = argv.proxy ? new HttpsProxyAgent('http://'+argv.proxy) : undefined;

// ---------- 4. Progress bar ---------- const bar = new cliProgress.SingleBar({ format: '{bar} {percentage}% | {value}/{total} | {target} | {status}', hideCursor: true }); bar.start(targets.length, 0, { target:'', status:'' });

// ---------- 5. Worker ---------- const results = []; let active = 0, index = 0;

function next() { if (index >= targets.length) return; const domain = targets[index++]; active++; bar.update(bar.value, { target:domain, status:'⏳' }); scan(domain).then(res => { results.push(res); bar.update(bar.value+1, { target:domain, status:res.ok?chalk.green('✓'):chalk.red('✗') }); active--; next(); }).catch(() => { bar.update(bar.value+1, { target:domain, status:chalk.red('ERR') }); active--; next(); }); }

function waitDone() { return new Promise(resolve => { const timer = setInterval(() => { if (active===0 && index>=targets.length) { clearInterval(timer); resolve(); } }, 250); }); }

// ---------- 6. Scan logic ---------- async function scan(host) { if (argv.ws) return scanWebSocket(host, port); if (argv.ssl) return scanTLS(host, port); return scanHTTP(host, port); }

function scanHTTP(host, port) { return new Promise(resolve => { const req = http.get({ host, port, path:'/', agent }, res => { res.destroy(); resolve({ host, port, mode:'HTTP', ok:true, status:res.statusCode }); }); req.on('error', () => resolve({ host, port, mode:'HTTP', ok:false })); req.setTimeout(5000, ()=>{ req.destroy(); resolve({ host, port, mode:'HTTP', ok:false, timeout:true }); }); }); }

function scanTLS(host, port) { return new Promise(resolve => { const socket = tls.connect({ host, port, servername:host, agent, rejectUnauthorized:false }, () => { const cert = socket.getPeerCertificate(); socket.destroy(); resolve({ host, port, mode:'SSL', ok:true, issuer:cert.issuer?.O, valid_to:cert.valid_to }); }); socket.on('error', () => resolve({ host, port, mode:'SSL', ok:false })); socket.setTimeout(5000, ()=>{ socket.destroy(); resolve({ host, port, mode:'SSL', ok:false, timeout:true }); }); }); }

function scanWebSocket(host, port) { return new Promise(resolve => { const ws = new WebSocket(ws://${host}:${port}, { agent, handshakeTimeout:5000 }); ws.on('open', () => { ws.terminate(); resolve({ host, port, mode:'WS', ok:true }); }); ws.on('error', () => resolve({ host, port, mode:'WS', ok:false })); }); }

// ---------- 7. Kick‑off ---------- for (let i=0;i<argv.concurrency && i<targets.length;i++) next(); waitDone().then(()=> { bar.stop(); const ok = results.filter(r=>r.ok).length; console.log(chalk.cyan(\nFinished: ${ok}/${targets.length} reachable.\n));

if (argv.out) { try { if (argv.out.endsWith('.json')) { fs.writeFileSync(argv.out, JSON.stringify(results,null,2)); } else { fs.writeFileSync(argv.out, results.map(r=>${r.ok?'✓':'✗'}\t${r.mode}\t${r.host}:${r.port}).join('\n')); } console.log(chalk.gray(Saved to ${argv.out})); } catch (e) { console.error(chalk.red(Could not write output file: ${e.message})); } } });

                                                                                                                                                                                                                                                                                                                                               
