(ns cryptopals.challenge.09
  (:require [clojure.test :refer :all]
            [cryptopals.core :refer :all]
            [cryptopals.block :refer [pkcs7-pad]]))

(deftest challenge-9-test
  (testing "Implement PKCS#7 padding"
    (let [bs (string->bytes "YELLOW SUBMARINE")
          result (pkcs7-pad 20 bs)]
      (is (= (count result) 20))
      (is (every? #(= 4 %) (take-last 4 result))))))
