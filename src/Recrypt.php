<?php
    namespace FlameDevelopment\Recrypt;
    /**
     * @author Martin Brooksbank <martin@flamedevelopment.co.uk>.
     * @date 19/11/2016
     * Inspired by http://php.net/manual/en/function.mcrypt-encrypt.php
     *
     */
    class Recrypt
    {
        /**
         * Generates a key using a string and salt
         * @param $string
         * @param $salt
         * @return string
         */
        public static function generateKey($string, $salt)
        {
            $blowfish_salt = bin2hex(openssl_random_pseudo_bytes(22));
            $hash = crypt($string, $salt . $blowfish_salt);

            return $hash;
        }

        /**
         * Encrypts or Decrypts a string
         * using the provided key.
         *
         * @param $key
         * @param $string
         * @return string
         * @throws \Exception
         */
        public static function encryptString($key, $string)
        {
            if (strlen($key) < 4)
            {
                throw new \Exception('Please provide a key that is more than 3 characters');
            }

            $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
            $iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
            $ciphertext = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key,
                $string, MCRYPT_MODE_CBC, $iv);
            $ciphertext = $iv . $ciphertext;
            $ciphertext_base64 = base64_encode($ciphertext);

            return $ciphertext_base64;
        }

        /**
         * Encrypts or Decrypts a string
         * using the provided key.
         *
         * @param $key
         * @param $string
         * @return string
         * @throws \Exception
         */
        public static function decryptString($key, $string)
        {
            if (strlen($key) < 4)
            {
                throw new \Exception('Please provide a key that is more than 3 characters');
            }
            $ciphertext_dec = base64_decode($string);
            $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
            $iv_dec = substr($ciphertext_dec, 0, $iv_size);
            $ciphertext_dec = substr($ciphertext_dec, $iv_size);
            $plaintext_dec = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key,
                $ciphertext_dec, MCRYPT_MODE_CBC, $iv_dec);

            return $plaintext_dec;
        }
    }