<?php

namespace webcoder31\ezxmldsig\Demo;

use webcoder31\ezxmldsig\XMLDSigToken;

/**
 * The attack lab: each attack alters a legitimate token, and the receiver
 * analyzes the result with the library.
 *
 * No attack runs vulnerable code: the lab shows what the current version
 * does with each forged token. The receiver of the lab is configured as the
 * receiver of the demo, with a replay memory of its own, created for each
 * attack: what the receiver has already seen does not change the outcome.
 */
final class AttackLab
{
    const ADVISORY_URL = 'https://github.com/webcoder31/ezxmldsig/security/advisories/';

    /**
     * The attacks. Each one has:
     * - title, summary: what the attacker does;
     * - base: the token it starts from ('plain', 'encrypted' or 'any');
     * - ghsa: the advisory of the flaw of the 0.x versions, if any;
     * - history: what the 0.x versions did, in one sentence.
     */
    const ATTACKS = [
        'tamper' => [
            'title' => 'Data tampering',
            'summary' => 'Change a value of the signed data, without signing again.',
            'base' => 'plain',
            'ghsa' => null,
            'history' => null,
        ],
        'wrapping' => [
            'title' => 'Signature wrapping',
            'summary' => 'Copy the signed ds:Object into ds:KeyInfo, which the signature does not cover, then forge the data of the original one.',
            'base' => 'plain',
            'ghsa' => 'GHSA-m876-q7cf-8gv2',
            'history' => 'In 0.x, xmlseclibs digested the copy while the token was read from ds:Signature/ds:Object, so forged data and timestamps passed for signed ones.',
        ],
        'copied-name' => [
            'title' => 'Look-alike certificate',
            'summary' => 'Forge the data and sign them with a certificate signed by its own key that copies the subject and issuer names of the legitimate one.',
            'base' => 'plain',
            'ghsa' => 'GHSA-p9rw-76gw-x7p2',
            'history' => 'In 0.x, a token signed with any key pair was valid, and isValidCertIssuer() passed on the copied names, unless the receiver also called isValidCertCA().',
        ],
        'ec-key' => [
            'title' => 'EC key substitution',
            'summary' => 'Forge the data, compute the digest again and replace the certificate with an EC one, keeping the RSA signature value.',
            'base' => 'plain',
            'ghsa' => 'GHSA-jwxg-xpg8-jr5p',
            'history' => 'In 0.x, openssl_verify() returned -1 for a key that does not suit the RSA algorithm, and -1 was taken for a valid signature, whatever the signature value.',
        ],
        'replay' => [
            'title' => 'Replay',
            'summary' => 'Submit a captured token a second time, unchanged.',
            'base' => 'any',
            'ghsa' => null,
            'history' => null,
        ],
        'expired' => [
            'title' => 'Expired token',
            'summary' => 'Submit a token the issuer signed earlier than the time to live allows: the timestamp is signed, so it cannot be moved forward.',
            'base' => 'plain',
            'ghsa' => null,
            'history' => null,
        ],
        'other-audience' => [
            'title' => 'Token for another receiver',
            'summary' => 'Submit to this receiver a token the issuer addressed to another one, "mail": same issuer, same key, same data.',
            'base' => 'plain',
            'ghsa' => null,
            'history' => 'In 1.0, a token named no audience: a token issued for one receiver was accepted by every receiver that trusted the issuer.',
        ],
        'past-expiry' => [
            'title' => 'Past its expiry',
            'summary' => 'Submit a token whose expiry, set by the issuer, has passed, although the time to live of the receiver would still accept it.',
            'base' => 'plain',
            'ghsa' => null,
            'history' => 'In 1.0, only the receiver set the time to live: the issuer could not shorten it.',
        ],
        'doctype' => [
            'title' => 'DOCTYPE and entities',
            'summary' => 'Add a document type declaration with nested entities (billion laughs) and an external entity that reads a local file.',
            'base' => 'any',
            'ghsa' => null,
            'history' => null,
        ],
        'ciphertext' => [
            'title' => 'Altered ciphertext',
            'summary' => 'Flip a byte of the encrypted content, then compute the digest and the signature again with a key the receiver trusts, so that the token reaches the decryption.',
            'base' => 'encrypted',
            'ghsa' => 'GHSA-w8x3-chg4-hvww',
            'history' => 'In 0.x, the decryption errors told apart padding and parsing failures, with RSA 1.5 and AES-CBC: the oracles that Bleichenbacher and Jager-Somorovsky attacks exploit.',
        ],
        'untrusted-ca' => [
            'title' => 'Untrusted CA',
            'summary' => 'Forge the data and sign them with a certificate that another CA issued, with the very subject of the legitimate one.',
            'base' => 'plain',
            'ghsa' => 'GHSA-p9rw-76gw-x7p2',
            'history' => 'In 0.x, no trust anchor was required: a certificate of any CA was accepted unless the receiver checked it on its own.',
        ],
        'script' => [
            'title' => 'Script in the data',
            'summary' => 'Have the issuer sign a value holding HTML and script. The token is valid: what matters is how its data are displayed.',
            'base' => 'plain',
            'ghsa' => 'GHSA-6f8c-4249-c8g5',
            'history' => 'In 0.x, getHTMLDump() wrote the data, errors and certificate fields without escaping, and loaded a script from a CDN.',
        ],
    ];

    /** The value the data-forging attacks write. */
    const FORGED_ROLE = 'King';

    /** The audience the "other-audience" attack addresses its token to. */
    const OTHER_AUDIENCE = 'mail';

    /** The value the "script" attack adds to the data. */
    const SCRIPT_VALUE = '<img src=x onerror="alert(document.domain)"><script>alert(1)</script>';

    /** @var Receiver */
    private $receiver;

    /** @var array User data of a token created for the lab. */
    private $data;

    /** @var array Algorithms of a token created for the lab. */
    private $algorithms;

    /** @var array|null Audiences and validity of a token created for the
    lab (see Issuer::create()). */
    private $claims;

    /**
     * @param Receiver $receiver The receiver that analyzes the tokens.
     * @param array $data The user data of the tokens the lab creates.
     * @param array $algorithms Their algorithms (see Issuer::create()).
     * @param array|null $claims Their audiences and validity, NULL for the
     *     default ones (see Issuer::create()).
     */
    public function __construct(Receiver $receiver, array $data = Issuer::DEFAULT_DATA, array $algorithms = [], array $claims = null)
    {
        $this->receiver = $receiver;
        $this->data = $data;
        $this->algorithms = $algorithms;
        $this->claims = $claims;
    }

    /**
     * Returns the attacks, as the interface lists them.
     *
     * @return array[]
     */
    public static function catalog()
    {
        $catalog = [];
        foreach (self::ATTACKS as $id => $attack)
        {
            $catalog[] = ['id' => $id] + $attack + [
                'advisory' => is_null($attack['ghsa']) ? null : self::ADVISORY_URL . $attack['ghsa'],
            ];
        }

        return $catalog;
    }

    /**
     * Runs an attack.
     *
     * @param string $id The attack.
     * @param string|null $lastXml The last token the issuer created, used
     *     as the starting point if the receiver accepts it and it is of the
     *     kind the attack needs.
     *
     * @return array
     *     - attack: the entry of catalog();
     *     - base: ['xml', 'origin' ('last' or 'fresh'), 'note', 'verdict'
     *       (the receiver's result for the legitimate token)];
     *     - forged: the altered token;
     *     - changes: what was changed, as sentences;
     *     - verdict: the receiver's result for the altered token (see
     *       Receiver::verify());
     *     - stoppedBy: the step that refused it (['id', 'label', 'by',
     *       'message']), or NULL;
     *     - htmlDump: for the "script" attack, the line of getHTMLDump()
     *       that shows the value.
     *
     * @throws \InvalidArgumentException For an unknown attack.
     */
    public function run($id, $lastXml = null)
    {
        if (!is_string($id) || !isset(self::ATTACKS[$id]))
        {
            throw new \InvalidArgumentException('Unknown attack.');
        }
        $attack = ['id' => $id] + self::ATTACKS[$id];
        $attack['advisory'] = is_null($attack['ghsa']) ? null : self::ADVISORY_URL . $attack['ghsa'];

        $base = $this->base($attack['base'], $lastXml);
        $store = new ReplayStore();
        $base['verdict'] = $this->receiver->verify($base['xml'], $store);
        if ('replay' !== $id)
        {
            // The altered token is submitted to a receiver that has not seen
            // the legitimate one.
            $store = new ReplayStore();
        }

        $method = 'attack' . str_replace(' ', '', ucwords(str_replace('-', ' ', $id)));
        list($forged, $changes) = $this->$method($base['xml']);
        $verdict = $this->receiver->verify($forged, $store);

        $result = [
            'attack' => $attack,
            'base' => $base,
            'forged' => $forged,
            'changes' => $changes,
            'verdict' => $verdict,
            'stoppedBy' => self::stoppedBy($verdict),
            'htmlDump' => null,
        ];
        if ('script' === $id)
        {
            $result['htmlDump'] = self::htmlDumpLine($this->receiver->analyze($forged));
        }

        return $result;
    }

    /**
     * Returns the token an attack starts from.
     */
    private function base($kind, $lastXml)
    {
        $reason = 'no token was created yet';
        if (is_string($lastXml) && '' !== $lastXml)
        {
            $verdict = $this->receiver->verify($lastXml, new ReplayStore());
            $encrypted = true === $verdict['token']['encrypted'];
            if (!$verdict['accepted'])
            {
                $reason = 'the last token is no longer accepted (' . self::stoppedBy($verdict)['label'] . ')';
            }
            elseif ('plain' === $kind && $encrypted)
            {
                $reason = 'this attack needs a token whose data are not encrypted';
            }
            elseif ('encrypted' === $kind && !$encrypted)
            {
                $reason = 'this attack needs an encrypted token';
            }
            else
            {
                return ['xml' => $lastXml, 'origin' => 'last', 'note' => 'Starts from the last token the issuer created.'];
            }
        }

        $token = Issuer::create($this->data, 'encrypted' === $kind, $this->algorithms, $this->claims);
        if (!is_null($token->getError()))
        {
            throw new \InvalidArgumentException('The issuer could not create a token: ' . $token->getError());
        }

        return [
            'xml' => $token->getXML(),
            'origin' => 'fresh',
            'note' => 'Starts from a token the issuer created for this attack, with the same data: ' . $reason . '.',
        ];
    }

    /**
     * Returns the first step that refused a token, or NULL if it was
     * accepted.
     */
    private static function stoppedBy(array $verdict)
    {
        foreach ($verdict['steps'] as $step)
        {
            if ('fail' === $step['status'])
            {
                return [
                    'id' => $step['id'],
                    'label' => $step['label'],
                    'by' => $step['by'],
                    'message' => $step['message'],
                ];
            }
        }

        return null;
    }

    private function attackTamper($xml)
    {
        $forge = new Forge($xml);
        $change = $forge->changeDataValue(self::FORGED_ROLE);

        return [$forge->xml(), [
            $change['path'] . ': "' . $change['old'] . '" becomes "' . $change['new'] . '" (base64 encoded in the token).',
            'DigestValue and SignatureValue are left as they were: computing them again needs the private key of the issuer.',
        ]];
    }

    private function attackWrapping($xml)
    {
        // The copy is inserted as text: cloning the node would let libxml
        // move its namespace declarations, which changes its canonical form.
        $forge = new Forge($xml);
        $copy = $forge->doc->saveXML($forge->node('/ds:Signature/ds:Object'));
        $position = strpos($xml, '</ds:KeyInfo>');
        if (false === $position)
        {
            throw new \InvalidArgumentException('The token has no ds:KeyInfo.');
        }
        $forge = new Forge(substr_replace($xml, $copy, $position, 0));
        $change = $forge->changeDataValue(self::FORGED_ROLE, '/ds:Signature/ds:Object');

        return [$forge->xml(), [
            'The signed ds:Object, with its Id="Token", is copied into ds:KeyInfo.',
            'In the original ds:Object, ' . $change['path'] . ': "' . $change['old'] . '" becomes "' . $change['new'] . '".',
            'The copy still matches DigestValue: a verifier that digests the first Id="Token" and reads the data from ds:Object accepts forged data.',
        ]];
    }

    private function attackCopiedName($xml)
    {
        $forge = new Forge($xml);
        $change = $forge->changeDataValue(self::FORGED_ROLE);
        $forge->redigest();
        $forge->resign(Certs::path('attacker.key.pem'), null, Certs::path('attacker.cert.pem'));

        return [$forge->xml(), [
            $change['path'] . ': "' . $change['old'] . '" becomes "' . $change['new'] . '".',
            'DigestValue computed again; SignatureValue computed with the attacker\'s key.',
            'X509Certificate replaced with attacker.cert.pem: signed by its own key, with the subject and issuer names of the legitimate certificate.',
        ]];
    }

    private function attackEcKey($xml)
    {
        $forge = new Forge($xml);
        $change = $forge->changeDataValue(self::FORGED_ROLE);
        $forge->redigest();
        $forge->replaceCertificate(Certs::path('ec.cert.pem'));

        return [$forge->xml(), [
            $change['path'] . ': "' . $change['old'] . '" becomes "' . $change['new'] . '".',
            'DigestValue computed again; SignatureValue left as it was.',
            'X509Certificate replaced with ec.cert.pem, an EC (P-256) certificate: verifying an RSA signature with its key makes openssl_verify() return -1, an error, not 0.',
        ]];
    }

    private function attackReplay($xml)
    {
        return [$xml, [
            'Nothing: the legitimate token is submitted a second time to the same receiver.',
        ]];
    }

    private function attackExpired($xml)
    {
        $ttl = $this->receiver->config()['ttl'];
        $issuedAt = new \DateTime('-' . ($ttl + 60) . ' seconds', new \DateTimeZone('UTC'));

        $forge = new Forge($xml);
        $timestamp = $forge->node('/ds:Signature/ds:Object/Token/TokenTimestamp');
        $old = $timestamp->textContent;
        $timestamp->nodeValue = $issuedAt->format(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT);
        $forge->redigest();
        $forge->resign(Certs::path('sign.key.pem'), Certs::SIGN_KEY_PASSWORD, Certs::path('sign.cert.pem'));

        return [$forge->xml(), [
            'TokenTimestamp: ' . $old . ' becomes ' . $timestamp->textContent . ', the time to live plus one minute ago.',
            'Digest and signature computed again with the issuer\'s own key: this is the token the issuer created then, as an attacker who captured it would submit it now.',
        ]];
    }

    private function attackOtherAudience($xml)
    {
        // The data of the legitimate token, read back by the receiver.
        $data = $this->receiver->analyze($xml)->getData();
        $data = is_array($data) ? $data : $this->data;
        $claims = (is_null($this->claims) ? Issuer::defaultClaims() : $this->claims);
        $claims['audience'] = [self::OTHER_AUDIENCE];
        $token = Issuer::create($data, false, $this->algorithms, $claims);

        return [$token->getXML(), [
            'The issuer creates a token with the same data, addressed to "' . self::OTHER_AUDIENCE . '": TokenAudience is "' . self::OTHER_AUDIENCE . '".',
            'Its digest and its signature are those of the trusted issuer: only the audience tells that this receiver is not the one the token is for.',
        ]];
    }

    private function attackPastExpiry($xml)
    {
        $issuedAt = new \DateTime('-30 seconds', new \DateTimeZone('UTC'));
        $expiresAt = new \DateTime('-10 seconds', new \DateTimeZone('UTC'));

        $forge = new Forge($xml);
        $token = $forge->node('/ds:Signature/ds:Object/Token');
        $timestamp = $forge->node('/ds:Signature/ds:Object/Token/TokenTimestamp');
        $timestamp->nodeValue = $issuedAt->format(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT);
        $expiries = $forge->xpath->query('TokenExpiry', $token);
        $expiry = $expiries->length > 0 ? $expiries->item(0) : $token->insertBefore($forge->doc->createElement('TokenExpiry'), $timestamp->nextSibling);
        $old = $expiry->textContent;
        $expiry->nodeValue = $expiresAt->format(XMLDSigToken::TOKEN_TIMESTAMP_FORMAT);
        $forge->redigest();
        $forge->resign(Certs::path('sign.key.pem'), Certs::SIGN_KEY_PASSWORD, Certs::path('sign.cert.pem'));

        return [$forge->xml(), [
            'TokenTimestamp: 30 seconds ago. TokenExpiry: ' . ('' === $old ? 'added, ' : $old . ' becomes ') . $expiry->textContent . ', 10 seconds ago.',
            'Digest and signature computed again with the issuer\'s own key: this is the token the issuer created 30 seconds ago, valid for 20 seconds, as an attacker who captured it would submit it now.',
        ]];
    }

    private function attackDoctype($xml)
    {
        $doctype = "<!DOCTYPE ds:Signature [\n"
            . "  <!ENTITY lol \"lol\">\n"
            . "  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n"
            . "  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n"
            . "  <!ENTITY xxe SYSTEM \"file:///etc/passwd\">\n"
            . "]>\n";
        $position = 0 === strpos($xml, '<?xml') ? strpos($xml, '?>') + 2 : 0;
        $forged = substr($xml, 0, $position) . "\n" . $doctype . ltrim(substr($xml, $position));

        return [$forged, [
            'A document type declaration is added before ds:Signature: nested entities, whose expansion grows tenfold at each level, and an external entity that would read /etc/passwd.',
            'The rest of the token is unchanged: its digest and signature are still valid.',
        ]];
    }

    private function attackCiphertext($xml)
    {
        $forge = new Forge($xml);
        $cipherValue = $forge->node('/ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue');
        $bytes = base64_decode($cipherValue->textContent);
        $offset = min(20, strlen($bytes) - 1);
        $bytes[$offset] = chr(ord($bytes[$offset]) ^ 0xff);
        $cipherValue->nodeValue = base64_encode($bytes);
        $forge->redigest();
        $forge->resign(Certs::path('sign.key.pem'), Certs::SIGN_KEY_PASSWORD, Certs::path('sign.cert.pem'));

        return [$forge->xml(), [
            'Byte ' . $offset . ' of the encrypted content (xenc:CipherValue of xenc:EncryptedData) is flipped.',
            'Digest and signature computed again with the issuer\'s key: a trusted signer submits the altered token, to learn something from how its decryption fails.',
        ]];
    }

    private function attackUntrustedCa($xml)
    {
        $forge = new Forge($xml);
        $change = $forge->changeDataValue(self::FORGED_ROLE);
        $forge->redigest();
        $forge->resign(Certs::path('rogue.key.pem'), null, Certs::path('rogue.cert.pem'));

        return [$forge->xml(), [
            $change['path'] . ': "' . $change['old'] . '" becomes "' . $change['new'] . '".',
            'DigestValue computed again; SignatureValue computed with the key of rogue.cert.pem.',
            'X509Certificate replaced with rogue.cert.pem: issued by "Kattegat Root CA", a CA the receiver does not trust, with the subject of the legitimate certificate.',
        ]];
    }

    private function attackScript($xml)
    {
        // The data of the legitimate token, read back by the receiver.
        $data = $this->receiver->analyze($xml)->getData();
        $data = is_array($data) ? $data : $this->data;
        $data['note'] = self::SCRIPT_VALUE;
        $token = Issuer::create($data, false, $this->algorithms, $this->claims);

        return [$token->getXML(), [
            'The issuer signs the same data with one more value, note: ' . self::SCRIPT_VALUE,
            'The token is legitimate: the receiver accepts it. The value is data, to be escaped wherever it is shown: this page writes it as text, and getHTMLDump() escapes it.',
        ]];
    }

    /**
     * Returns the line of getHTMLDump() that shows the "script" value.
     */
    private static function htmlDumpLine(XMLDSigToken $token)
    {
        foreach (explode("\n", $token->getHTMLDump()) as $line)
        {
            if (false !== strpos($line, '&lt;script&gt;'))
            {
                return trim($line);
            }
        }

        return null;
    }
}
