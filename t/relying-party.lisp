(in-package #:cl-openid)

(in-suite :cl-openid)

(test nonce-universal-time
  (is (= (encode-universal-time 23 42 17 9 11 2007 0)
         (nonce-universal-time "2007-11-09T17:42:23Zfoobar42"))))

(test nonce-universal-time/random
  (for-all ((sec (gen-integer :min 0 :max 59))
            (min (gen-integer :min 0 :max 59))
            (hr (gen-integer :min 0 :max 23))
            (day (gen-integer :min 1 :max 28))
            (mon (gen-integer :min 1 :max 12))
            (year (gen-integer :min 1970 :max 2100))
            (uniq (gen-string)))
    (is (= (encode-universal-time sec min hr day mon year 0)
           (nonce-universal-time (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ~A"
                                         year mon day hr min sec uniq))))))
