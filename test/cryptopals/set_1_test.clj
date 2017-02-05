(ns cryptopals.set-1-test
  (:require [clojure.string :as string]
            [clojure.test :refer :all]
            [cryptopals.core :refer :all]))

(deftest challenge-1-test
  (testing "Convert hex to base64"
    (let [input "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
          expected "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"]
      (is (= expected (hex->base64 input))))))

(deftest challenge-2-test
  (testing "Fixed XOR"
    (let [h1 "1c0111001f010100061a024b53535009181c"
          h2 "686974207468652062756c6c277320657965"
          expected "746865206b696420646f6e277420706c6179"]
      (is (= expected
             (bytes->hex (xor-bytes (hex->bytes h1) (hex->bytes h2))))))))

(deftest challenge-3-test
  (testing "Single-byte XOR cipher"
    (is (= \X (->> "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
                   hex->bytes
                   enumerate-guesses
                   (sort-by :score)
                   first
                   :ch)))))

(deftest challenge-4-test
  (testing "Detect single-character XOR"
    (is (= "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f"
           (->> "resources/4.txt"
                slurp
                string/split-lines
                (map (comp enumerate-guesses hex->bytes))
                flatten
                (sort-by :score)
                first
                :input)))))

(deftest challenge-5-test
  (testing "Implement repeating-key XOR"
    (is (= "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
           (bytes->hex (xor-cipher (string->bytes "ICE")
                                   (string->bytes "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")))))))

(deftest challenge-6-test
  (testing "Break repeating-key XOR"
    (let [input (->> "resources/6.txt" slurp base64->bytes)
          key-size (determine-key-size input)]
      (is (= "Terminator X: Bring the noise"
             (break-repeating-key-xor key-size input))))))

(deftest challenge-7-test
  (testing "AES in ECB mode"
    (let [k (string->bytes "YELLOW SUBMARINE")
          ciphertext (->> "resources/7.txt" slurp base64->bytes)
          plaintext (aes-ecb-decrypt k ciphertext)]
      (is (-> (bytes->string plaintext)
              (.startsWith "I'm back and I'm ringin' the bell"))))))

(deftest challenge-8-test
  (testing "Detect AES in ECB mode"
    (is (= "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a"
           (->> "resources/8.txt"
                slurp
                string/split-lines
                (filter has-duplicate-blocks?)
                first)))))
