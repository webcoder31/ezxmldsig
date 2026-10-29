/**
 * Serves requests against the Node.js library ezxmldsig-js, over HTTP, for
 * the tests of the interoperability between the two libraries (see
 * bin/js-ezxmldsig, which runs it, and tests/helpers/Js.php, which calls it).
 *
 * POST / takes a JSON array of requests and answers a JSON array of results,
 * one per request; GET /health answers 200 once the library is loaded. A
 * request is an object whose "command" is:
 *
 * - "create": creates a token, with createXMLToken(), or with
 *   createSecureXMLToken() when "cryptCert" is given. Fields: "data",
 *   "signKey", "signCert", "signKeyPassword", "cryptCert", "cryptKey",
 *   "cryptKeyPassword", "options". Result: the analysis below, of the
 *   created token.
 *
 * - "analyze": analyzes "xml" with analyzeXMLToken(), or with
 *   analyzeSecureXMLToken() when "cryptKey" is given. Fields: "xml",
 *   "cryptKey", "cryptKeyPassword", "options", and "ttl" for isOutOfDate()
 *   (default: 60).
 *
 * - "verifySeal": verifies the sealed container "container" ({"bytes":
 *   base64}) with verifySeal(). Fields: "container", "options" (its CRLs and
 *   OCSP responses as {"bytes": base64}). Result: the verdict, as
 *   tests/fixtures/seal/generate.ts records it in verdicts.json ("valid",
 *   "error", "level", "files", "signingTime", "timestampTime", "signer"),
 *   and "revocationChecked".
 *
 * - "xmlCryptoCreate": creates a token with xml-crypto, and encrypts its
 *   content with xml-encryption when "encrypted" is true, as the
 *   interoperability page of the documentation site shows it: data "name"
 *   and "city", audience "receiver", valid 300 seconds. Fields:
 *   "encrypted", "signKey", "signKeyPassword", "signCert", "cryptCert".
 *   Result: {"xml"}.
 *
 * - "xmlCryptoRead": reads "xml" with xml-crypto, and xml-encryption when
 *   its content is encrypted: the signature verified with "signCert", the
 *   data read from the content the signature covers, decrypted with
 *   "cryptKey". Result: "valid", and "data" and "digest" (the SHA-256, in
 *   base64, of the canonical content the signature covers, as xml-crypto
 *   computes it), or "error" when the signature is not valid.
 *
 * The requests and results are those of test/php/ezxmldsig.php of the
 * Node.js library, which serves the same commands with the PHP library, but
 * "verifySeal" and the commands of xml-crypto, ported from
 * test/token/interop.test.ts of the Node.js library. xml-crypto,
 * xml-encryption and @xmldom/xmldom are those the Node.js library installs.
 * Paths of keys and certificates are those of the PHPUnit container: the
 * repository is seen at the same place, read-only. Token data that are not
 * UTF-8 text are given as {"bytes": base64}. An exception thrown by the
 * library gives {"exception": message, "class": its class} instead of a
 * result.
 */

import { createHash, createPrivateKey, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';

// The library: a clone at a tag, or a working copy (see bin/js-ezxmldsig).
const { XMLDSigToken } = await import('/ezxmldsig-js/dist/token/index.js');
const { verifySeal } = await import('/ezxmldsig-js/dist/seal/index.js');
// Third-party libraries: the versions the library depends on.
const dependency = createRequire('/ezxmldsig-js/package.json');
const { SignedXml } = dependency('xml-crypto');
const xmlenc = dependency('xml-encryption');
const { DOMParser, XMLSerializer } = dependency('@xmldom/xmldom');

const PORT = 8080;

type Request = Record<string, any>;

/** Data from JSON: {"bytes": base64} becomes bytes. */
function fromJson(data: any): any {
  if (Array.isArray(data)) {
    return data.map(fromJson);
  }
  if (data !== null && typeof data === 'object') {
    if (Object.keys(data).length === 1 && typeof data.bytes === 'string') {
      return new Uint8Array(Buffer.from(data.bytes, 'base64'));
    }
    return Object.fromEntries(Object.entries(data).map(([name, value]) => [name, fromJson(value)]));
  }
  return data;
}

/** Data to JSON: bytes become {"bytes": base64}. */
function toJson(data: any): any {
  if (data instanceof Uint8Array) {
    return { bytes: Buffer.from(data).toString('base64') };
  }
  if (Array.isArray(data)) {
    return data.map(toJson);
  }
  if (data !== null && typeof data === 'object') {
    return Object.fromEntries(Object.entries(data).map(([name, value]) => [name, toJson(value)]));
  }
  return data;
}

/** What the accessors of a token return. */
function describe(token: any, ttl: number) {
  return {
    xml: token.getXML(),
    prettyXml: token.getPrettyXML(),
    isSignatureValid: token.isSignatureValid(),
    isDigestValueOk: token.isDigestValueOk(),
    isSignatureValueOk: token.isSignatureValueOk(),
    isCertTrusted: token.isCertTrusted(),
    isDataEncrypted: token.isDataEncrypted(),
    now: Math.floor(Date.now() / 1000),
    isOutOfDate: token.isOutOfDate(ttl),
    error: token.getError(),
    anomalies: token.getAnomalies(),
    data: toJson(token.getData()),
    timestamp: token.getTimestamp(),
    tokenId: token.getTokenId(),
    audience: token.getAudience(),
    expiry: token.getExpiry(),
    certDN: token.getCertDN(),
    certSubject: token.getCertSubject(),
    certIssuer: token.getCertIssuer(),
    certValidFrom: token.getCertValidFrom(),
    certValidTo: token.getCertValidTo(),
  };
}

/** The verdict on a seal. */
function verdict(result: any) {
  return {
    valid: result.isValid(),
    error: result.getError(),
    level: result.getLevel(),
    files: result.getFiles(),
    signingTime: result.getSigningTime()?.toISOString() ?? null,
    timestampTime: result.getTimestampTime()?.toISOString() ?? null,
    signer: result.getSigningCertificate()?.getDN() ?? null,
    revocationChecked: result.isRevocationChecked(),
  };
}

const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
const isoDate = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

/** The first child element of a node: whitespace may come before it. */
function firstElement(parent: any): any {
  for (let child = parent.firstChild; child !== null; child = child.nextSibling) {
    if (child.nodeType === 1) {
      return child;
    }
  }
  return null;
}

/** Creates a token with xml-crypto, and xml-encryption if it is encrypted. */
async function xmlCryptoCreate(request: Request): Promise<string> {
  const now = new Date();
  let token = '<Token>'
    + `<TokenTimestamp>${isoDate(now)}</TokenTimestamp>`
    + `<TokenId>${randomBytes(16).toString('hex')}</TokenId>`
    + `<TokenExpiry>${isoDate(new Date(now.getTime() + 300e3))}</TokenExpiry>`
    + '<TokenAudience>receiver</TokenAudience>'
    + `<TokenData><name Algorithm="base64">${b64('Ragnar Lothbrok')}</name><city Algorithm="base64">${b64('Kattegat & Hedeby')}</city></TokenData>`
    + '</Token>';
  if (request.encrypted) {
    token = await new Promise((resolve, reject) => xmlenc.encrypt(token, {
      rsa_pub: readFileSync(request.cryptCert),
      pem: readFileSync(request.cryptCert),
      encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
      keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
    }, (error: Error | null, result: string) => (error ? reject(error) : resolve(result))));
  }
  // xml-crypto places a signature inside an existing document: sign in a
  // throwaway root, then keep the signature alone, as the document element.
  // Its private key cannot have a password: the key is decrypted first.
  const privateKey = createPrivateKey({ key: readFileSync(request.signKey), passphrase: request.signKeyPassword }).export({ type: 'pkcs8', format: 'pem' });
  const signature = new SignedXml({
    privateKey,
    publicCert: readFileSync(request.signCert),
    canonicalizationAlgorithm: C14N,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    objects: [{ content: token, attributes: { Id: 'Token' } }],
  });
  signature.addReference({ xpath: "//*[@Id='Token']", digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256', transforms: [C14N] });
  signature.computeSignature('<root/>', { prefix: 'ds' });
  const doc = new DOMParser().parseFromString(signature.getSignedXml(), 'text/xml');
  return `<?xml version="1.0"?>\n${new XMLSerializer().serializeToString(doc.documentElement.firstChild)}`;
}

/** The values of the data: an element holding a single text node is a value, an element holding elements is nested values. */
function readValues(parent: any): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  for (const element of Array.from(parent.childNodes) as any[]) {
    if (element.nodeType !== 1) {
      continue;
    }
    const leaf = element.childNodes.length === 1 && element.firstChild?.nodeType === 3;
    values[element.nodeName] = !leaf
      ? readValues(element)
      : element.getAttribute('Algorithm') === 'base64' ? Buffer.from(element.textContent ?? '', 'base64').toString('utf8') : element.textContent ?? '';
  }
  return values;
}

/** Reads a token with xml-crypto, and xml-encryption if it is encrypted. */
async function xmlCryptoRead(request: Request) {
  const xml: string = request.xml;
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const signature = new SignedXml({ publicCert: readFileSync(request.signCert) });
  signature.loadSignature(doc.documentElement);
  let valid: boolean;
  try {
    valid = signature.checkSignature(xml);
  } catch (e) {
    return { valid: false, error: e instanceof Error ? e.message : String(e) };
  }
  if (!valid) {
    return { valid: false, error: 'Invalid signature' };
  }
  const [signed] = signature.getSignedReferences();
  let content = firstElement(new DOMParser().parseFromString(signed, 'text/xml').documentElement);
  if (content?.localName === 'EncryptedData') {
    const plain: string = await new Promise((resolve, reject) => xmlenc.decrypt(new XMLSerializer().serializeToString(content), { key: readFileSync(request.cryptKey) },
      (error: Error | null, result: string) => (error ? reject(error) : resolve(result))));
    content = new DOMParser().parseFromString(plain, 'text/xml').documentElement;
  }
  if (content?.localName !== 'Token') {
    throw new Error(`The signed content is ${content?.localName}, not Token.`);
  }
  const tokenData = Array.from(content.childNodes as any[]).find((child) => child.nodeName === 'TokenData');
  return { valid: true, data: readValues(tokenData), digest: createHash('sha256').update(signed).digest('base64') };
}

/** Runs one request. */
async function run(request: Request) {
  const options = request.options ?? {};
  const ttl = request.ttl ?? XMLDSigToken.TOKEN_DEFAULT_TTL;
  switch (request.command) {
    case 'create':
      return describe(
        request.cryptCert !== undefined
          ? XMLDSigToken.createSecureXMLToken(
              fromJson(request.data),
              request.signKey,
              request.signCert,
              request.cryptKey ?? null,
              request.cryptCert,
              request.signKeyPassword ?? null,
              request.cryptKeyPassword ?? null,
              options,
            )
          : XMLDSigToken.createXMLToken(fromJson(request.data), request.signKey, request.signCert, request.signKeyPassword ?? null, options),
        ttl,
      );
    case 'analyze':
      return describe(
        request.cryptKey !== undefined
          ? XMLDSigToken.analyzeSecureXMLToken(request.xml, request.cryptKey, request.cryptKeyPassword ?? null, options)
          : XMLDSigToken.analyzeXMLToken(request.xml, options),
        ttl,
      );
    case 'verifySeal':
      return verdict(verifySeal(fromJson(request.container), fromJson(options)));
    case 'xmlCryptoCreate':
      return { xml: await xmlCryptoCreate(request) };
    case 'xmlCryptoRead':
      return xmlCryptoRead(request);
    default:
      throw new Error('Unknown command!');
  }
}

createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/health') {
    res.end('ok');
    return;
  }
  if (req.method !== 'POST' || req.url !== '/') {
    res.statusCode = 404;
    res.end();
    return;
  }
  const chunks: Buffer[] = [];
  req.on('data', (chunk: Buffer) => chunks.push(chunk));
  req.on('end', () => {
    let requests: unknown;
    try {
      requests = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      requests = null;
    }
    if (!Array.isArray(requests)) {
      res.statusCode = 400;
      res.end('The requests must be a JSON array.\n');
      return;
    }
    Promise.all(requests.map(async (request: Request) => {
      try {
        return await run(request);
      } catch (e) {
        return { exception: e instanceof Error ? e.message : String(e), class: e instanceof Error ? e.constructor.name : typeof e };
      }
    })).then((results) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(results));
    });
  });
}).listen(PORT);
