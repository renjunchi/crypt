<?php
namespace Dvdfab\Crypt;

class Aes
{
    /**
     * @var string 加密方式
     */
    private $method = 'AES-128-CBC';

    /**
     * @var string 加密密钥
     */
    private $encrypt_key;

    /**
     * @var string 向量
     */
    private $iv = '82bmc9132afvp524';

    /**
     * @var string 签名密钥
     */
    private $sign_secret;

    /**
     * @param string $method
     */
    public function setMethod(string $method): void
    {
        $this->method = $method;
    }

    /**
     * @param string $encrypt_key
     */
    public function setEncryptKey(string $encrypt_key): void
    {
        $this->encrypt_key = $encrypt_key;
    }

    /**
     * @param string $iv
     */
    public function setIv(string $iv): void
    {
        $this->iv = $iv;
    }

    /**
     * @param string $sign_secret
     */
    public function setSignSecret(string $sign_secret): void
    {
        $this->sign_secret = $sign_secret;
    }

    /**
     * 签名
     * @param array $data
     * @return string
     */
    public function signature(array $data): string
    {
        $query = $this->buildQuery($data);
        return md5(md5($this->sign_secret . $query));
    }

    /**
     * 验签
     * @param array $data
     * @return bool
     */
    public function verifySignature(array $data): bool
    {
        $sign = $data['sign'];
        unset($data['sign']);

        $signature = $this->signature($data);
        return $signature === $sign;
    }

    /**
     * 加密
     * @param array $data
     * @return string
     */
    public function encrypt(array $data): string
    {
        $data = json_encode($data);
        $encrypt = openssl_encrypt($data,
            $this->method,
            $this->encrypt_key,
            OPENSSL_RAW_DATA,
            $this->iv);
        return base64_encode($encrypt);
    }

    /**
     * 解密
     * @param string $encrypt
     * @return array|mixed
     */
    public function decrypt(string $encrypt)
    {
        $encrypt = base64_decode($encrypt);
        $decrypt = openssl_decrypt($encrypt,
            $this->method,
            $this->encrypt_key,
            OPENSSL_RAW_DATA,
            $this->iv);
        return $decrypt ? json_decode($decrypt, true) : [];
    }

    /**
     * @param array $data
     * @return string
     */
    private function buildQuery(array $data): string
    {
        ksort($data);
        return http_build_query($data);
    }
}
