/** Shared SMB codecs and contracts. Built, acceptance pending; no enforcement claim. */
export { allConstants, constant, bound } from './constants.js';
export { jcs } from './jcs.js';
export { parseStrict } from './parse-strict.js';
export { validate, validateBytes, edges, normalizeBootId, ReplyMatcher } from './wire.js';
export { encodeFrame, decodeFrame, readFrame } from './frame.js';
