<?php

namespace webcoder31\ezxmldsig\Tests\helpers;

/**
 * Validation of seals by DSS (Digital Signature Service, the validator of
 * the European Commission), which does not go through the code under test.
 * A port of test/helpers/dss.ts of the Node.js library.
 *
 * DSS runs at the URL of EZXMLDSIG_DSS_URL, which bin/test sets when it
 * starts DSS with bin/dss (unless DSS=0): it trusts
 * tests/fixtures/seal/certs/root.cert.pem and tsa-root.cert.pem, and
 * reaches the CRL and OCSP of the test PKI at pki.ezxmlseal.test.
 *
 * The tests that need it are in the group dss. They are skipped, with the
 * reason, when the URL is not set; in continuous integration (CI=true), they
 * fail instead. The workflow runs them in a job of their own, and leaves
 * them out of the others (--exclude-group dss).
 */
class Dss
{
    /** The certificate the published CRLs revoke; no other one is. */
    const REVOKED = 'revoked';

    /**
     * Why the tests that need DSS are skipped, or NULL when they run.
     */
    public static function skipReason()
    {
        if (false !== self::url() || 'true' === getenv('CI'))
        {
            return null;
        }
        return 'EZXMLDSIG_DSS_URL is not set: run the tests with bin/test, which starts DSS (unless DSS=0).';
    }

    /**
     * Sends a container to DSS, with its default validation policy, and
     * returns what the tests read from its reports: 'containerType', and
     * for each signature 'format' (such as XAdES-BASELINE-B), 'indication',
     * 'subIndication', 'scope' (the names of the files it covers), 'errors'
     * (of the AdES validation; the qualification, which needs an EU trusted
     * list, is left out), 'signatureIntact', 'references' (each 'type',
     * 'found', 'intact') and 'trusted' (the subjects of the certificates
     * DSS trusts, among those it used); 'revocationOrigins': where each
     * revocation data DSS used comes from (INPUT_DOCUMENT: the seal;
     * EXTERNAL: fetched...).
     */
    public static function validate($container, $name = 'seal.asice')
    {
        $url = self::url();
        if (false === $url)
        {
            throw new \RuntimeException('EZXMLDSIG_DSS_URL is not set: run the tests with bin/test.');
        }
        $context = stream_context_create(['http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\nAccept: application/json\r\n",
            'content' => json_encode(['signedDocument' => ['bytes' => base64_encode($container), 'name' => $name], 'originalDocuments' => [], 'policy' => null, 'signatureId' => null]),
            'timeout' => 120,
            'ignore_errors' => true,
        ]]);
        $body = @file_get_contents($url . '/services/rest/validation/validateSignature', false, $context);
        $status = isset($http_response_header[0]) ? $http_response_header[0] : 'no answer';
        if (false === $body || false === strpos($status, ' 200 '))
        {
            throw new \RuntimeException('DSS answered ' . $status . ': ' . $body);
        }
        $report = json_decode($body, true);
        $simple = $report['SimpleReport'];
        $diagnostic = $report['DiagnosticData'];
        $values = function ($list) { return array_map(function ($item) { return is_string($item) ? $item : $item['value']; }, $list ?? []); };
        $trusted = [];
        foreach ($diagnostic['Certificate'] ?? [] as $cert)
        {
            if (isset($cert['Trusted']['value']) && true === $cert['Trusted']['value'])
            {
                foreach ($cert['SubjectDistinguishedName'] as $dn)
                {
                    if ('RFC2253' === $dn['Format'])
                    {
                        $trusted[] = $dn['value'];
                    }
                }
            }
        }
        $signatures = [];
        foreach ($simple['signatureOrTimestampOrEvidenceRecord'] ?? [] as $entry)
        {
            $signature = isset($entry['Signature']) ? $entry['Signature'] : $entry;
            $diag = [];
            foreach ($diagnostic['Signature'] ?? [] as $candidate)
            {
                if ($candidate['Id'] === $signature['Id'])
                {
                    $diag = $candidate;
                }
            }
            $signatures[] = [
                'format' => $signature['SignatureFormat'],
                'indication' => $signature['Indication'],
                'subIndication' => isset($signature['SubIndication']) ? $signature['SubIndication'] : null,
                'scope' => array_map(function ($scope) { return $scope['name']; }, $signature['SignatureScope'] ?? []),
                'errors' => $values(isset($signature['AdESValidationDetails']['Error']) ? $signature['AdESValidationDetails']['Error'] : null),
                'signatureIntact' => isset($diag['BasicSignature']) && true === $diag['BasicSignature']['SignatureIntact'] && true === $diag['BasicSignature']['SignatureValid'],
                'references' => array_map(function ($matcher) {
                    return ['type' => $matcher['type'], 'found' => true === $matcher['DataFound'], 'intact' => true === $matcher['DataIntact']];
                }, isset($diag['DigestMatcher']) ? $diag['DigestMatcher'] : []),
                'trusted' => $trusted,
            ];
        }
        return [
            'containerType' => isset($simple['ContainerType']) ? $simple['ContainerType'] : null,
            'signatures' => $signatures,
            'revocationOrigins' => array_map(function ($revocation) { return $revocation['Origin']; }, $diagnostic['Revocation'] ?? []),
        ];
    }

    /**
     * Publishes the CRLs of the test PKI where its certificates say they
     * are: intermediate.crl (the seal certificates), root.crl (the
     * intermediate CA), tsa-root.crl (the time-stamping authority). Every
     * test publishes the same ones, which revoke
     * tests/fixtures/seal/certs/revoked.cert.pem only. DSS keeps them one
     * second in its cache (bin/dss): the method returns once it is past.
     */
    public static function publishTestCrls()
    {
        $dir = dirname(__DIR__) . '/.cache/dss/pki/';
        if (!is_dir($dir))
        {
            mkdir($dir, 0777, true);
        }
        $crls = [
            'intermediate' => TestCrl::make(['revoked' => [['cert' => self::REVOKED, 'date' => time() - 3600]]]),
            'root' => TestCrl::make(['issuer' => 'root']),
            'tsa-root' => TestCrl::make(['issuer' => 'tsa-root']),
        ];
        foreach ($crls as $name => $crl)
        {
            file_put_contents($dir . $name . '.crl.part', $crl);
            rename($dir . $name . '.crl.part', $dir . $name . '.crl');
        }
        usleep(1500000);
    }

    private static function url()
    {
        $url = getenv('EZXMLDSIG_DSS_URL');
        return false === $url || '' === $url ? false : rtrim($url, '/');
    }
}
