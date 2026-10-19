// Public surface of the harness-agnostic core.
export { Engine, InspectionError, NOTICE_MARKER } from './engine.js'
export { CATEGORIES, HIGH_RISK, IRREVERSIBLE, NOTICE_NAME, PLACEHOLDER_RE, placeholder } from './categories.js'
export { DEFAULT_RESTORE_POLICY, restoreToolArguments } from './restore.js'
export { luhn } from './detectors/contact.js'
export { GITLEAKS_RULE_COUNT } from './detectors/gitleaks.js'
