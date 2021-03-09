<?php
// Inspiration from https://deliciousbrains.com/php-encryption-methods/
// This version by https://github.com/ged3000
//
// Dependencies:
// "composer require google/cloud-kms" 
// php libsodium extension

/* Require composer modules */
require 'vendor/autoload.php';


namespace Google\Cloud\Samples\Auth;

putenv("GOOGLE_APPLICATION_CREDENTIALS=/path/to/google/auth/details");

$projectId   = 'google-api-projectId'; // Get this from the google API - via the setup link at https://deliciousbrains.com/php-encryption-methods/
$location    = 'global';
$keyRingId   = 'example-keyring';
$cryptoKeyId = 'example-key';

use Google\ApiCore\ApiException;
use Google\Cloud\Kms\V1\CryptoKey;
use Google\Cloud\Kms\V1\CryptoKey\CryptoKeyPurpose;
use Google\Cloud\Kms\V1\KeyManagementServiceClient as Kms;
use Google\Cloud\Kms\V1\KeyRing;

class KeyManager{
	private $kms;
	private $projectId;    // Plaintext project ID
	private $locationId;   // Plaintext location ID
	private $locationRef;  // Encoded location reference
	private $keyRingId;    // Plaintext keyring ID
	private $keyRingRef;   // Encoded keyring reference
	private $cryptoKeyId;  // Plaintext key ID
	private $criptoKeyRef; // Encoded key reference
	
	public function __construct(Kms $kms, $projectId, $locationId, $keyRingId, $cryptoKeyId){
		$this->kms            = $kms;
		$this->projectId      = $projectId;
		$this->locationId     = $locationId;
		$this->locationRef    = $this->kms::locationName($this->projectId, $this->locationId);
		$this->keyRingId      = $keyRingId;
		$this->keyRingRef     = $this->kms::keyRingName($this->projectId, $this->locationId, $this->keyRingId);
		$this->cryptoKeyId    = $cryptoKeyId;
		$this->criptoKeyRef   = $this->kms::cryptoKeyName($this->projectId, $this->locationId, $this->keyRingId, $this->cryptoKeyId);
		
		try {
			$keyRing = $this->kms->getKeyRing($this->keyRingRef);
		} catch (ApiException $e) {
			if ($e->getStatus() === 'NOT_FOUND') {
				$keyRing = new KeyRing();
				$keyRing->setName($this->keyRingRef);
 				$this->kms->createKeyRing($this->locationRef, $this->keyRingId, $keyRing);
			}
		}
		
		try {
			$cryptoKey = $this->kms->getCryptoKey($this->criptoKeyRef);
		} catch (ApiException $e) {
			if ($e->getStatus() === 'NOT_FOUND') {
				$cryptoKey = new CryptoKey();
				$cryptoKey->setPurpose(CryptoKeyPurpose::ENCRYPT_DECRYPT);
				$cryptoKey = $this->kms->createCryptoKey($this->keyRingRef, $this->cryptoKeyId, $cryptoKey);
			}
		}
	}
	
	public function encrypt($data){
		$key        = random_bytes(SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
		$nonce      = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
		$ciphertext = sodium_crypto_secretbox($data, $nonce, $key);
		
		return [
			'data'   => base64_encode($nonce . $ciphertext),
			'secret' => $this->encryptKey($key),
		];
	}
	
	public function encryptKey($key){
		$secret = base64_encode($key);
		
		$response = $this->kms->encrypt(
			$this->criptoKeyRef,
			$secret
		);
		
		return $response->getCiphertext();
	}
	
	public function decryptKey($secret){
		$response = $this->kms->decrypt(
			$this->criptoKeyRef,
			$secret
		);
		
		return base64_decode($response->getPlaintext());
	}
	
	public function decrypt($secret, $data){
		$decoded    = base64_decode($data);
		$key        = $this->decryptKey($secret);
		$nonce      = mb_substr($decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit');
		$ciphertext = mb_substr($decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit');
		
		return sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
	}
	
}

$keyManager = new KeyManager(
	new Kms(),
	$projectId,
	$location,
	$keyRingId,
	$cryptoKeyId
);

$encrypted = $keyManager->encrypt('My secret text');

$unencrypted = $keyManager->decrypt($encrypted['secret'],$encrypted['data']);

print_r($encrypted);
print_r($unencrypted);
