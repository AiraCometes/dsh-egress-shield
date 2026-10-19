#!/usr/bin/env node
// Compare egress-shield with Gitleaks, TruffleHog and Microsoft Presidio on the
// same labelled, fictitious corpus (test/support/labelled-corpus.mjs).
//
// External tools are optional and only used here (dev-time); point at them with
//   GITLEAKS_BIN, TRUFFLEHOG_BIN, PRESIDIO_PYTHON (a python with presidio-analyzer,
//   en_core_web_sm and ja_core_news_sm installed).
// TruffleHog runs with --no-verification so nothing is sent anywhere.

import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildLabelledCorpus } from '../test/support/labelled-corpus.mjs'
import { buildEngine } from '../src/setup.js'

const corpus = buildLabelledCorpus()
const dir = mkdtempSync(join(tmpdir(), 'egress-compare-'))
const file = join(dir, 'corpus.txt')
writeFileSync(file, corpus.map((l) => l.text).join('\n') + '\n')

function score(name, detectedLines, ms, rssMb) {
  const byCat = {}
  let fp = 0
  let negatives = 0
  corpus.forEach((l, i) => {
    if (l.category === 'NONE') {
      negatives++
      if (detectedLines.has(i)) fp++
      return
    }
    const key = l.hard ? `${l.category} (hard)` : l.category
    byCat[key] ??= { tp: 0, n: 0 }
    byCat[key].n++
    if (detectedLines.has(i)) byCat[key].tp++
  })
  return { name, byCat, fp, negatives, ms, rssMb }
}

// ---- egress-shield
function runSelf() {
  const before = process.memoryUsage().rss
  const t0 = performance.now()
  const { engine } = buildEngine({ discover: false })
  const detected = new Set()
  corpus.forEach((l, i) => {
    const out = engine.redactString(l.text, engine.scope(`line-${i}`), {}).text
    if (l.category === 'NONE' ? out !== l.text : !out.includes(l.value)) detected.add(i)
  })
  return score(
    'egress-shield (this repo)',
    detected,
    performance.now() - t0,
    (process.memoryUsage().rss - before) / 2 ** 20,
  )
}

// Peak child RSS via getrusage (portable where GNU time is not installed).
const RUSAGE =
  'import resource,subprocess,sys\nr=subprocess.run(sys.argv[1:],capture_output=True,text=True)\nsys.stdout.write(r.stdout)\nsys.stderr.write(r.stderr+"\\n@@RSS@@%d"%resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)'

function timed(cmd, args) {
  const t0 = performance.now()
  const r = spawnSync('python3', ['-c', RUSAGE, cmd, ...args], { encoding: 'utf8', maxBuffer: 1 << 28 })
  const ms = performance.now() - t0
  const kb = Number(/@@RSS@@(\d+)/.exec(r.stderr ?? '')?.[1])
  return { r, ms, rssMb: Number.isFinite(kb) ? kb / 1024 : NaN }
}

function runGitleaks(bin) {
  const report = join(dir, 'gitleaks.json')
  const { ms, rssMb } = timed(bin, [
    'dir',
    dir,
    '--report-format',
    'json',
    '--report-path',
    report,
    '--no-banner',
    '--exit-code',
    '0',
    '--log-level',
    'error',
  ])
  const detected = new Set(
    JSON.parse(readFileSync(report, 'utf8'))
      .filter((f) => f.File.endsWith('corpus.txt'))
      .map((f) => f.StartLine - 1),
  )
  return score('Gitleaks', detected, ms, rssMb)
}

function runTrufflehog(bin) {
  const { r, ms, rssMb } = timed(bin, [
    'filesystem',
    file,
    '--json',
    '--no-verification',
    '--no-update',
    '--log-level=-1',
  ])
  const detected = new Set()
  for (const line of r.stdout.split('\n')) {
    if (!line.trim()) continue
    try {
      detected.add(JSON.parse(line).SourceMetadata.Data.Filesystem.line - 1)
    } catch {}
  }
  return score('TruffleHog (no verification)', detected, ms, rssMb)
}

function runPresidio(python) {
  const script = join(dir, 'presidio_run.py')
  writeFileSync(
    script,
    `
import json, re, sys
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
provider = NlpEngineProvider(nlp_configuration={"nlp_engine_name": "spacy", "models": [
  {"lang_code": "en", "model_name": "en_core_web_sm"}, {"lang_code": "ja", "model_name": "ja_core_news_sm"}]})
nlp = provider.create_engine()
registry = RecognizerRegistry(supported_languages=["en", "ja"])
registry.load_predefined_recognizers(languages=["en", "ja"], nlp_engine=nlp)
analyzer = AnalyzerEngine(nlp_engine=nlp, registry=registry, supported_languages=["en", "ja"])
# Only entity types relevant to this comparison (no DATE_TIME / NRP / ORG noise).
ENTITIES = ["PERSON", "LOCATION", "EMAIL_ADDRESS", "CREDIT_CARD", "IP_ADDRESS", "PHONE_NUMBER", "US_SSN", "IBAN_CODE", "URL"]
hits = []
for i, line in enumerate(open(sys.argv[1], encoding="utf-8").read().split("\\n")):
    if not line: continue
    lang = "ja" if re.search(r"[\\u3040-\\u30ff\\u4e00-\\u9fff]", line) else "en"
    res = analyzer.analyze(text=line, language=lang, score_threshold=0.4, entities=ENTITIES)
    if res: hits.append(i)
print(json.dumps(hits))
`,
  )
  const { r, ms, rssMb } = timed(python, [script, file])
  let detected = new Set()
  try {
    detected = new Set(JSON.parse(r.stdout.trim().split('\n').pop()))
  } catch {
    console.error('presidio failed:', r.stderr.slice(-500))
  }
  return score('Presidio (spaCy en_sm + ja_sm)', detected, ms, rssMb)
}

const results = [runSelf()]
// External scanners run only when their location is given explicitly.
const { GITLEAKS_BIN: gitleaks, TRUFFLEHOG_BIN: trufflehog, PRESIDIO_PYTHON: python } = process.env
if (gitleaks && existsSync(gitleaks)) results.push(runGitleaks(gitleaks))
if (trufflehog && existsSync(trufflehog)) results.push(runTrufflehog(trufflehog))
if (python && existsSync(python)) results.push(runPresidio(python))

const categories = [...new Set(results.flatMap((r) => Object.keys(r.byCat)))].toSorted()
const pct = (x) => (x.n ? `${Math.round((100 * x.tp) / x.n)}%` : '-')
let md = `| category (n) | ${results.map((r) => r.name).join(' | ')} |\n|---|${results.map(() => '---').join('|')}|\n`
for (const c of categories) {
  const n = results[0].byCat[c]?.n ?? 0
  md += `| ${c} (${n}) | ${results.map((r) => (r.byCat[c] ? pct(r.byCat[c]) : '-')).join(' | ')} |\n`
}
md += `| false positives on ${results[0].negatives} negatives | ${results.map((r) => `${r.fp}`).join(' | ')} |\n`
md += `| wall time (ms, ${corpus.length} lines) | ${results.map((r) => r.ms.toFixed(0)).join(' | ')} |\n`
md += `| peak/added memory (MB) | ${results.map((r) => (Number.isFinite(r.rssMb) ? r.rssMb.toFixed(0) : '?')).join(' | ')} |\n`
console.log(md)
