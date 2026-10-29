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
 * The requests and results are those of test/php/ezxmldsig.php of the
 * Node.js library, which serves the same commands with the PHP library, but
 * "verifySeal".
 * Paths of keys and certificates are those of the PHPUnit container: the
 * repository is seen at the same place, read-only. Token data that are not
 * UTF-8 text are given as {"bytes": base64}. An exception thrown by the
 * library gives {"exception": message, "class": its class} instead of a
 * result.
 */

import { createServer } from 'node:http';

// The library: a clone at a tag, or a working copy (see bin/js-ezxmldsig).
const { XMLDSigToken } = await import('/ezxmldsig-js/dist/token/index.js');
const { verifySeal } = await import('/ezxmldsig-js/dist/seal/index.js');

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

/** Runs one request. */
function run(request: Request) {
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
    const results = requests.map((request: Request) => {
      try {
        return run(request);
      } catch (e) {
        return { exception: e instanceof Error ? e.message : String(e), class: e instanceof Error ? e.constructor.name : typeof e };
      }
    });
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(results));
  });
}).listen(PORT);
