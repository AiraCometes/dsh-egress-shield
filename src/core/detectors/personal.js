// Person names and postal addresses (Japanese and English).
//
// Deterministic rules only: a user-supplied term list (the reliable path),
// contextual cues (氏名:, 様, Dear, Author:), a common-surname dictionary, and
// structural address grammars. Free-form names with no cue and no dictionary
// hit are NOT detected; users add such names to their private term list.

// Common Japanese surnames (frequency-ordered, abbreviated). Used only together
// with an honorific or a space-separated given name, never on their own.
export const JA_SURNAMES = (
  '佐藤 鈴木 高橋 田中 伊藤 渡辺 山本 中村 小林 加藤 吉田 山田 佐々木 山口 松本 井上 木村 林 斎藤 清水 ' +
  '山崎 森 池田 橋本 阿部 石川 山下 中島 石井 小川 前田 岡田 長谷川 藤田 後藤 近藤 村上 遠藤 青木 坂本 ' +
  '斉藤 福田 太田 西村 藤井 金子 岡本 藤原 中野 三浦 原田 中川 松田 竹内 小野 田村 中山 和田 石田 森田 ' +
  '上田 原 内田 柴田 酒井 宮崎 横山 高木 安藤 宮本 大野 小島 谷口 今井 工藤 高田 増田 丸山 杉山 村田 ' +
  '大塚 新井 小山 平野 藤本 河野 上野 野口 武田 松井 千葉 岩崎 菅原 木下 久保 佐野 野村 松尾 市川 菊地 ' +
  '杉本 古川 大西 島田 水野 桜井 高野 渡部 吉川 山内 西田 飯田 菊池 西川 小松 北村 安田 五十嵐 川口 平田 ' +
  '関 中田 久保田 服部 東 岩田 土屋 川崎 福島 本田 辻 樋口 秋山 田口 永井 山中 中西 吉村 川上 石原 大橋 ' +
  '松岡 馬場 浅野 荒木 大久保 星野 片山 松下 大川 堀 宮田 熊谷 小池 内藤 松村 大谷 森本 平井 岩本 ' +
  '片岡 西山 吉野 南 竹田 福井 堀内 小田 中尾 坂口 本間 小西 長田 早川 須藤 細川 新田 北川 堀田 栗原 ' +
  '大石 望月 飯塚 宮下 吉岡 青山 松永 稲垣 富田 黒田 上原 宇野 三上 高山 杉浦 安達 根本 荒井 大島 武藤'
).split(' ')

// Titles that follow a surname but are not given names.
const NOT_GIVEN = new Set([
  '部長',
  '課長',
  '社長',
  '係長',
  '主任',
  '先生',
  '教授',
  '会長',
  '専務',
  '常務',
  '店長',
  '所長',
  '院長',
  '室長',
  '理事',
  '選手',
  '監督',
  '議員',
  '弁護士',
  '医師',
  '様',
  'さん',
])

const surnameAlt = [...JA_SURNAMES].toSorted((a, b) => b.length - a.length).join('|')
// First-character lookahead lets the regex engine skip most positions before
// trying the ~200-way alternation (≈3× faster on large inputs).
const surnameFirst = [...new Set(JA_SURNAMES.map((s) => s[0]))].join('')
const JA_CHARS = '一-龯々〆ヵヶ'
const JA_ANY = '一-龯々〆ヵヶぁ-んァ-ヶー'
// A name may follow a particle (私は田中さんと…) but not another kanji/katakana word.
const JA_WORD = '一-龯々〆ヵヶァ-ヶー'

const JA_HONORIFIC_RE = new RegExp(
  `(?<![${JA_WORD}])(?=[${surnameFirst}])(?:${surnameAlt})(?:[ \\u3000]?[${JA_ANY}]{1,4}?)?(?=様|さま|さん|殿|氏|先生|くん|君|ちゃん)`,
  'g',
)
const JA_SPACED_RE = new RegExp(
  `(?<![${JA_WORD}])(?=[${surnameFirst}])(?:${surnameAlt})[ \\u3000]([${JA_CHARS}]{1,3}|[ぁ-ん]{2,4}|[ァ-ヶー]{2,6})(?![${JA_WORD}])`,
  'g',
)
const JA_CONTEXT_RE = new RegExp(
  `(?:氏名|名前|お名前|フルネーム|担当者?|代表者|作成者|申請者|申込者|宛名|差出人|受取人|契約者|患者名?|署名|著者|名義人?|ご依頼主|お届け先)[ \\t\\u3000]*[:：][ \\t\\u3000]*([${JA_CHARS}]{1,4}[ \\u3000]?[${JA_ANY}]{1,5}|[ァ-ヶー]{2,8}[ \\u3000][ァ-ヶー]{2,8}|[A-Z][a-z]{1,20} [A-Z][a-z]{1,20})`,
  'g',
)

const PREFECTURES =
  '北海道|青森県|岩手県|宮城県|秋田県|山形県|福島県|茨城県|栃木県|群馬県|埼玉県|千葉県|東京都|神奈川県|新潟県|富山県|石川県|福井県|山梨県|長野県|岐阜県|静岡県|愛知県|三重県|滋賀県|京都府|大阪府|兵庫県|奈良県|和歌山県|鳥取県|島根県|岡山県|広島県|山口県|徳島県|香川県|愛媛県|高知県|福岡県|佐賀県|長崎県|熊本県|大分県|宮崎県|鹿児島県|沖縄県'
const NUM = '0-9０-９一二三四五六七八九十百〇'
const DASH = '\\-－ー‐−'
// Prefecture … block number, optionally followed by building and room.
const JA_ADDRESS_RE = new RegExp(
  `(?:〒[ \\u3000]?\\d{3}[${DASH}]\\d{4}[ \\u3000]*)?(?:${PREFECTURES})[^\\s、。,，」』\\n]{1,40}?[${NUM}]+(?:丁目|番地?|号|[${DASH}])[${NUM}${DASH}番地号の]{0,20}(?:[ \\u3000]?[^\\s、。,，」』\\n]{1,30}?[${NUM}]{1,5}号室)?`,
  'g',
)
// City/ward … chōme without a prefecture.
const JA_CITY_ADDRESS_RE = new RegExp(
  `(?<![${JA_WORD}])[${JA_CHARS}]{1,6}[市区町村][${JA_ANY}]{1,12}?[${NUM}]+丁目(?:[${NUM}]+(?:番地?|[${DASH}]))?[${NUM}${DASH}番地号の]{0,12}`,
  'g',
)
const JA_POSTAL_RE = /(?:〒|郵便番号[ \t　]*[:：]?)[ \t　]*\d{3}[-－ー‐]\d{4}/g

const EN_STREET =
  'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Parkway|Pkwy|Circle|Cir|Highway|Hwy|Square|Sq'
const EN_ADDRESS_RE = new RegExp(
  `\\b\\d{1,6}[ \\t]+(?:[A-Z][A-Za-z0-9.'-]{0,30}[ \\t]+){1,4}(?:${EN_STREET})\\.?(?:,?[ \\t]+(?:Apt|Apartment|Suite|Ste|Unit|#)\\.?[ \\t]*[A-Za-z0-9-]{1,8})?(?:,[ \\t]*[A-Z][A-Za-z .'-]{1,40})?(?:,[ \\t]*[A-Z]{2}[ \\t]+\\d{5}(?:-\\d{4})?)?`,
  'g',
)

const EN_TITLE_RE =
  /\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof)\.?[ \t]+([A-Z][a-zA-Z'-]{1,30}(?:[ \t]+[A-Z][a-zA-Z'-]{1,30}){0,2})/g
const EN_CONTEXT_RE =
  /\b(?:[Nn]ame|[Ff]ull [Nn]ame|[Aa]uthor|[Cc]ontact|[Oo]wner|[Aa]ssignee|[Rr]eporter|[Ss]igned(?:-off-by| by)?|[Ss]incerely|[Rr]egards|[Dd]ear|[Ff]rom|[Cc]c|[Pp]atient|[Cc]ustomer|[Cc]ardholder|[Cc]o-[Aa]uthored-[Bb]y)\b[ \t]*[:,]?[ \t]*(?:\r?\n[ \t]*)?([A-Z][a-z'-]{1,30}(?:[ \t]+[A-Z]\.)?[ \t]+[A-Z][a-zA-Z'-]{1,30})(?![a-z])/g
const EN_NOT_NAME = new Set([
  'The',
  'This',
  'That',
  'My',
  'Your',
  'Our',
  'All',
  'New',
  'List',
  'Team',
  'Project',
  'File',
  'Error',
  'Do',
  'To',
  'Data',
  'User',
  'Admin',
  'Test',
  'Hello',
  'World',
  'Request',
  'Response',
  'Config',
  'Default',
  'Server',
  'Client',
  'Service',
  'Support',
  'Customer',
  'Name',
  'Unknown',
  'None',
  'Null',
  'True',
  'False',
  'Example',
  'Sample',
  'Github',
  'GitHub',
  'Google',
  'Microsoft',
])

function each(re, text, fn) {
  re.lastIndex = 0
  let m
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++
      continue
    }
    fn(m)
  }
}

function pushTail(spans, m, value, category, rule) {
  const s = m.index + m[0].lastIndexOf(value)
  spans.push({ s, e: s + value.length, c: category, r: rule })
}

const HONORIFIC_HINT = /様|さま|さん|殿|氏|先生|くん|君|ちゃん/
const JA_CONTEXT_HINT =
  /氏名|名前|フルネーム|担当|代表者|作成者|申請者|申込者|宛名|差出人|受取人|契約者|患者|署名|著者|名義|依頼主|届け先/
const PREFECTURE_HINT = /[都道府県]/
const EN_STREET_HINT = new RegExp(`\\b(?:${EN_STREET})\\b`)
const EN_TITLE_HINT = /\b(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof)\b/
const EN_CONTEXT_HINT =
  /name|author|contact|owner|assignee|reporter|signed|sincerely|regards|dear|from|cc|patient|customer|cardholder|co-authored/i

export function detectPersonal(text, spans, options = {}) {
  // Each family of rules runs only when its required cue occurs in the text.
  const ja = /[\u3040-\u30ff\u4e00-\u9fff]/.test(text)
  if (ja) {
    if (HONORIFIC_HINT.test(text)) {
      each(JA_HONORIFIC_RE, text, (m) => {
        const name = m[0].trim()
        if (NOT_GIVEN.has(name)) return
        spans.push({ s: m.index, e: m.index + m[0].length, c: 'PERSON', r: 'ja-honorific' })
      })
    }
    if (/[ \u3000]/.test(text)) {
      each(JA_SPACED_RE, text, (m) => {
        if (NOT_GIVEN.has(m[1])) return
        spans.push({ s: m.index, e: m.index + m[0].length, c: 'PERSON', r: 'ja-spaced' })
      })
    }
    if (JA_CONTEXT_HINT.test(text)) each(JA_CONTEXT_RE, text, (m) => pushTail(spans, m, m[1], 'PERSON', 'ja-context'))
    if (PREFECTURE_HINT.test(text))
      each(JA_ADDRESS_RE, text, (m) =>
        spans.push({ s: m.index, e: m.index + m[0].length, c: 'ADDRESS', r: 'ja-address' }),
      )
    if (text.includes('丁目'))
      each(JA_CITY_ADDRESS_RE, text, (m) =>
        spans.push({ s: m.index, e: m.index + m[0].length, c: 'ADDRESS', r: 'ja-city-address' }),
      )
    if (text.includes('〒') || text.includes('郵便番号'))
      each(JA_POSTAL_RE, text, (m) =>
        spans.push({ s: m.index, e: m.index + m[0].length, c: 'ADDRESS', r: 'ja-postal' }),
      )
  }
  if (EN_STREET_HINT.test(text))
    each(EN_ADDRESS_RE, text, (m) =>
      spans.push({ s: m.index, e: m.index + m[0].length, c: 'ADDRESS', r: 'en-address' }),
    )
  if (options.englishNames !== false) {
    if (EN_TITLE_HINT.test(text)) {
      each(EN_TITLE_RE, text, (m) => {
        if (!EN_NOT_NAME.has(m[1].split(/[ \t]/)[0])) pushTail(spans, m, m[1], 'PERSON', 'en-title')
      })
    }
    if (EN_CONTEXT_HINT.test(text)) {
      each(EN_CONTEXT_RE, text, (m) => {
        const words = m[1].split(/[ \t]+/)
        if (words.some((w) => EN_NOT_NAME.has(w))) return
        pushTail(spans, m, m[1], 'PERSON', 'en-context')
      })
    }
  }
}
