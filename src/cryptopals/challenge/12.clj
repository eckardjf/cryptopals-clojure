(ns cryptopals.challenge.12
  (:require [clojure.test :refer :all]
            [clojure.test.check :as tc]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [cryptopals.core :refer :all]
            [cryptopals.block :refer [pkcs7-pad aes-ecb-encrypt]]))

(def plaintext (-> (str "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
                        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
                        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
                        "YnkK")
                   base64->bytes))

(def unknown-block-size 16)
(def unknown-key (rand-bytes unknown-block-size))

(defn oracle-fn
  ([] (oracle-fn plaintext))
  ([suffix]
   (fn [bs]
     (->> (concat bs suffix)
          (pkcs7-pad unknown-block-size)
          (aes-ecb-encrypt unknown-key)))))

(defn determine-block-size [f]
  (let [[a b] (distinct
               (map (fn [n]
                      (count (f (byte-array n (byte \A)))))
                    (range)))]
    (- b a)))

(defn ecb? [f block-size]
  (apply = (->> (f (byte-array (* block-size 2) (byte \A)))
                (partition block-size)
                (take 2))))

(defn recover-next-byte [f block-size known]
  (let [position (count known)
        block (int (quot position block-size))
        pad (dec (- block-size (mod position block-size)))
        prefix (byte-array pad (byte \A))
        target (nth (partition block-size (f prefix)) block)]
    (first (filter (fn [i]
                     (let [payload (concat prefix known [i])]
                       (= target (nth (partition block-size (f payload)) block))))
                   (range 256)))))

(defn recover-suffix [f]
  (let [block-size (determine-block-size f)]
    (when (ecb? f block-size)
      (loop [known []]
        (let [next-byte (recover-next-byte f block-size known)]
          ;; don't like this check - what if there is a valid 1 byte?
          (if (= 1 next-byte)
            (-> known byte-array bytes->string)
            (recur (conj known next-byte))))))))

(defspec sentinel-byte-holds 100
  (prop/for-all [rand-string (gen/fmap #(apply str %)
                                       (gen/vector gen/char-alpha 1 100))]
                (= rand-string (recover-suffix (oracle-fn (string->bytes rand-string))))))

(deftest challenge-12-test
  (testing "Byte-at-a-time ECB decryption (Simple)"
    (is (= (recover-suffix (oracle-fn))
           (str "Rollin' in my 5.0\n"
                "With my rag-top down so my hair can blow\n"
                "The girlies on standby waving just to say hi\n"
                "Did you stop? No, I just drove by\n")))))
