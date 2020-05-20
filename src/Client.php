<?php

namespace CombellAPI;

use Exception;

use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * @see https://api.combell.com/v2/documentation
 */
class Client
{

    public const API_HOST = 'https://api.combell.com';

    /**
     * @var string
     */
    protected $apiKey, $apiSecret;

    /**
     * @var HttpClientInterface
     */
    protected $httpClient;
    
    protected $rateLimitRemaining;
    protected $rateLimitReset;

    /**
     * @var OutputInterface
     */
    protected $out;

    protected function __construct(
        string $apiKey,
        string $apiSecret,
        HttpClientInterface $httpClient,
        OutputInterface $out
    ) {
        $this->apiKey = $apiKey;
        $this->apiSecret = $apiSecret;
        $this->httpClient = $httpClient;
        $this->out = $out;
    }

    public static function create(
        string $apiKey,
        string $apiSecret,
        OutputInterface $out
    ): self {
        return new static(
            $apiKey,
            $apiSecret,
            HttpClient::create(),
            $out
        );
    }

    public static function createPassword(): string
    {
        return bin2hex(openssl_random_pseudo_bytes(10));    // 20 characters
    }

    protected function log(string $msg, bool $veryVerbose = false)
    {
        $this->out->write(
            $msg,
            false,
            $veryVerbose ? OutputInterface::VERBOSITY_VERY_VERBOSE : OutputInterface::VERBOSITY_VERBOSE
        );
    }


    public function getAccounts(string $identifier = null): array
    {
        [, , $accounts] = $this->request(
            Request::create(
                self::API_HOST . '/v2/accounts',
                Request::METHOD_GET,
                array_merge(
                    [
                        'asset_type' => 'linux_hosting',
                        'skip' => 0,
                        'take' => 1337,
                    ],
                    $identifier ? [
                        'identifier' => $identifier
                    ] : []
                )
            )
        );
        
        return $accounts;
    }

    public function createAccount(string $domain, int $servicePack): int
    {
        $this->log("Creating account for domain '$domain'... ");

        $accountId = $this->provision(
            Request::create(
                self::API_HOST . '/v2/accounts',
                Request::METHOD_POST,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'identifier' => $domain,
                        'servicepack_id' => $servicePack,
                        'ftp_password' => self::createPassword(),
                    ]
                )
            )
        );

        $this->log("success! id: $accountId\n");

        return $accountId;
    }

    public function configureAll(string $domain)
    {
        $this->configureSSH($domain);
        $this->configurePHP($domain);
        $this->configureWebServer($domain);
    }

    public function toggleFTP(
        string $domain,
        bool $enable = false
    ) {
        $this->log("Configuring FTP... ");

        $this->request(
            Request::create(
                self::API_HOST . "/v2/linuxhostings/$domain/ftp/configuration",
                Request::METHOD_PUT,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'enabled' => $enable,
                    ]
                )
            )
        );

        $this->log("<info>✓</info>\n");
    }

    public function configureSSH(
        string $domain,
        bool $enable = true,
        array $keys = []
    ) {
        $this->log("Configuring SSH... ");

        $this->request(
            Request::create(
                self::API_HOST . "/v2/linuxhostings/$domain/ssh/configuration",
                Request::METHOD_PUT,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'enabled' => $enable,
                    ]
                )
            )
        );

        if ($enable && !empty($keys)) {
            $this->log("Enabled ✓. Adding keys... ", true);

            foreach ($keys as $key) {
                try {
                    $this->request(
                        Request::create(
                            self::API_HOST . "/v2/linuxhostings/$domain/ssh/keys",
                            Request::METHOD_POST,
                            [],
                            [],
                            [],
                            ['CONTENT_TYPE' => 'application/json'],
                            json_encode(
                                [
                                    'public_key' => $key,
                                ]
                            )
                        )
                    );
                } catch (Exception $e) {
                    if (strpos($e->getMessage(), 'ssh_key_already_exists') === false) {
                        throw $e;
                    }
                }

                $this->log("✓ ", true);
            }
        } else {
            $this->log("Disabled ✓.", true);
        }

        $this->log("<info>all ✓</info>\n");
    }

    public function configurePHP(
        string $domain,
        string $version = '7.3',
        int $memoryLimit = 256
    ) {
        $this->log("Configuring PHP... ");

        $this->request(
            Request::create(
                self::API_HOST . "/v2/linuxhostings/$domain/phpsettings/version",
                Request::METHOD_PUT,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'version' => $version,
                    ]
                )
            )
        );

        $this->log("version: $version. ", true);

        $this->request(
            Request::create(
                self::API_HOST . "/v2/linuxhostings/$domain/phpsettings/memorylimit",
                Request::METHOD_PUT,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'memory_limit' => $memoryLimit,
                    ]
                )
            )
        );

        $this->log("memory limit: {$memoryLimit}M. ", true);

        $this->log("<info>✓</info>\n");
    }

    public function configureWebServer(
        string $domain,
        bool $gzip = true,
        bool $http2 = true,
        bool $letsEncrypt = true,
        bool $autoRedirectToHTTPS = true
    ) {
        $this->log("Configuring web server... ");

        $this->request(
            Request::create(
                self::API_HOST . "/v2/linuxhostings/$domain/settings/gzipcompression",
                Request::METHOD_PUT,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'enabled' => $gzip,
                    ]
                )
            )
        );

        $this->log("GZIP ✓. ", true);

        $this->request(
            Request::create(
                self::API_HOST . "/v2/linuxhostings/$domain/sites/$domain/http2/configuration",
                Request::METHOD_PUT,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'enabled' => $http2,
                    ]
                )
            )
        );

        $this->log("HTTP/2 ✓. ", true);

        $this->request(
            Request::create(
                self::API_HOST . "/v2/linuxhostings/$domain/sslsettings/$domain/letsencrypt",
                Request::METHOD_PUT,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'enabled' => $letsEncrypt,
                    ]
                )
            )
        );

        $this->log("Let's Encrypt ✓. ", true);

        $this->request(
            Request::create(
                self::API_HOST . "/v2/linuxhostings/$domain/sslsettings/$domain/autoredirect",
                Request::METHOD_PUT,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'enabled' => $autoRedirectToHTTPS,
                    ]
                )
            )
        );

        $this->log("auto-redirect ✓. ", true);

        $this->log("<info>✓</info>\n");
    }

    public function listDatabases(int $offset = 0, int $limit = 50): array
    {
        [, , $content] = $this->request(
            Request::create(
                self::API_HOST . '/v2/mysqldatabases',
                Request::METHOD_GET,
                [
                    'skip' => $offset,
                    'take' => $limit,
                ]
            )
        );

        return $content;
    }

    public function createDatabase(int $accountId, string $name, string $password): string
    {
        return $this->provision(
            Request::create(
                self::API_HOST . '/v2/mysqldatabases',
                Request::METHOD_POST,
                [],
                [],
                [],
                ['CONTENT_TYPE' => 'application/json'],
                json_encode(
                    [
                        'database_name' => $name,
                        'account_id' => $accountId,
                        'password' => $password,
                    ]
                )
            )
        );
    }


    protected function provision(Request $request): string
    {
        [$status, $headers] = $this->request($request);

        if ($status >= 400) {
            throw new Exception("Could not provision job");
        }

        $jobURL = $headers['location'][0];

        do {
            sleep(1);
            [$status, , $content] = $this->request(Request::create(self::API_HOST . $jobURL));
            if ($content && ($content['status'] ?? '') == 'failed') {
                throw new APIException("Could not create database", $status);
            }
        } while ($status == 200);

        if ($status == 201) {    // Created
            return basename($content['resource_links'][0]);    // '/v2/mysqldatabases/ID123_newdb'
        } else {
            throw new APIException($content, $status);
        }
    }

    /**
     * @param Request $request
     * @return array    [int $status, string[] $headers, string $body]
     * @throws APIException
     */
    protected function request(Request $request): array
    {
        $this->sign($request);

        if (
            $this->rateLimitRemaining !== null &&  // not first request
            $this->rateLimitRemaining <= 0
        ) {
            $this->log('Rate limit hit. Waiting for next interval zzz', true);
            sleep($this->rateLimitReset);
            $this->log(' done!', true);
        }
        
        $response = $this->httpClient->request(
            $request->getMethod(),
            $request->getUri(),
            array_merge(
                ['headers' => $request->headers->all()],
                $request->getContent() ? ['body' => $request->getContent()] : []
            )
        );

        $status = $response->getStatusCode();
        $headers = $response->getHeaders(false);
        $body = $response->getContent(false) ? $response->toArray(false) : '';

        $this->rateLimitRemaining   = (int)current($headers['x-ratelimit-remaining']);
        $this->rateLimitReset       = (int)current($headers['x-ratelimit-reset']);
        
        if ($status >= 400) {
            throw new APIException(
                $body ? "{$body['error_text']} ({$body['error_code']})" : "HTTP Status $status (no response body)",
                $status
            );
        }

        return [$status, $headers, $body];
    }

    protected function sign(Request $request)
    {
        $time = time();
        $nonce = uniqid();

        $uri = $request->getUri();
        $path = substr($uri, strlen(self::API_HOST));
        $body = $request->getContent();

        if ($body !== '') {
            $body = base64_encode(md5($body, true));
        }

        $valueToSign = $this->apiKey
            . strtolower($request->getMethod())
            . urlencode($path)
            . $time
            . $nonce
            . $body;
        $signature = base64_encode(hash_hmac('sha256', $valueToSign, $this->apiSecret, true));

        $request->headers->set('Authorization', "hmac $this->apiKey:$signature:$nonce:$time");
    }
}
