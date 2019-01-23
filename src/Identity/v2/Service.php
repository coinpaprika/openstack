<?php

declare(strict_types=1);

namespace OpenStack\Identity\v2;

use GuzzleHttp\ClientInterface;
use OpenStack\Common\Auth\IdentityService;
use OpenStack\Common\Service\AbstractService;
use OpenStack\Identity\v2\Models\Catalog;
use OpenStack\Identity\v2\Models\Token;

/**
 * Represents the OpenStack Identity v2 service.
 *
 * @property \OpenStack\Identity\v2\Api $api
 */
class Service extends AbstractService implements IdentityService
{
    public static function factory(ClientInterface $client): self
    {
        return new static($client, new Api());
    }

    public function authenticate(array $options = []): array
    {

        $definition = $this->api->postToken();
        $authOptions = array_intersect_key($options, $definition['params']);
        if (!empty($options['cachedToken'])) {
            $token = $this->generateTokenFromCache($options['cachedToken']);

            if ($token->hasExpired()) {
                throw new \RuntimeException(sprintf('Cached token has expired on "%s".', $token->expires->format(\DateTime::ISO8601)));
            }
        } else {
            $token = $this->generateToken($authOptions);
        }

        if (!empty($options['cachedCatalog'])) {
            $catalog = $this->generateCatalogFromCache($options['cachedCatalog']);
        } else {
            $catalog = $this->generateCatalog($options);
        }

        $serviceUrl = $this->getServiceUrl($catalog, $options);

        return [$token, $serviceUrl];
    }

    /**
     * Generates a new authentication token.
     *
     * @param array $options {@see \OpenStack\Identity\v2\Api::postToken}
     *
     * @return Models\Token
     */
    public function generateToken(array $options = []): Token
    {
        return $this->model(Token::class, $this->execute($this->api->postToken(), $options));
    }

    /**
     * Generates a new services catalog.
     *
     * @param array $options {@see \OpenStack\Identity\v2\Api::postToken}
     *
     * @return Models\Catalog
     */

    public function generateCatalog(array $options = []): Catalog
    {
        return $this->model(Catalog::class, $this->execute($this->api->postToken(), $options));
    }

    public function getServiceUrl(Catalog $catalog, array $options = []): string
    {
        return $catalog->getServiceUrl(
            $options['catalogName'],
            $options['catalogType'],
            $options['region'],
            $options['urlType']
        );
    }

    public function generateTokenFromCache(array $cachedToken = []): Token
    {
        return $this->model(Token::class)->populateFromArray($cachedToken);
    }

    public function generateCatalogFromCache(array $cachedCatalog = []): Catalog
    {
        return $this->model(Catalog::class)->populateFromArray($cachedCatalog);
    }


}
