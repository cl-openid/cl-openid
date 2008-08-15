(in-package #:cl-openid)

(in-suite :cl-openid)

(defparameter *aget-test-case*
  '((:foo . 1)
    ("bar" . 2)
    (7 . 3)))

(test aget
  (is (null (aget :xyzzy *aget-test-case*)))
  (is (null (aget "xyzzy" *aget-test-case*)))
  (is (eql 1 (aget :foo *aget-test-case*)))
  (is (eql 2 (aget "bar" *aget-test-case*)))
  (is (eql 3 (aget 7 *aget-test-case*))))

(test btwoc
  ;; OpenID Authentication 2.0, 4.2.  Integer Representations
  ;; Non-normative example:
  (dolist (test-case '((0 . #(0))
                       (127 . #(127))
                       (128 . #(0 128))
                       (255 . #(0 255))
                       (32768 . #(0 128 0))))
    (let ((octets (btwoc (car test-case))))
      (is (equalp octets (cdr test-case)))
      (is (= (ironclad:octets-to-integer octets)
             (car test-case))))))

(test btwoc/random
  (for-all ((i (gen-integer :min 0)))
    (let ((octets (btwoc i)))
      (is (< (aref octets 0) 128))
      (is (= i (ironclad:octets-to-integer octets))))))

(test base64-btwoc/random
  (for-all ((i (gen-integer :min 0)))
    (is (= i (cl-base64:base64-string-to-integer (base64-btwoc i))))))

(defparameter *vector-12345678* (make-array 3
                                            :element-type '(unsigned-byte 8)
                                            :initial-contents '(188 97 78)))

(defparameter *btwoc-12345678* (make-array 4
                                           :element-type '(unsigned-byte 8)
                                           :initial-contents '(0 188 97 78)))

(test ensure-integer
  (is (= 12345678 (ensure-integer *vector-12345678*)))
  (is (= 12345678 (ensure-integer *btwoc-12345678*)))
  (is (= 12345678 (ensure-integer "vGFO")))
  (is (= 12345678 (ensure-integer 12345678))))

(test ensure-integer/random
  (for-all ((i (gen-integer :min 0)))
    (is (= i (ensure-integer i)))
    (is (= i (ensure-integer (integer-to-octets i))))
    (is (= i (ensure-integer (btwoc i))))
    (is (= i (ensure-integer (integer-to-base64-string i))))))

(test ensure-vector
  (is (equalp *btwoc-12345678* (ensure-vector 12345678)))
  (is (equalp *vector-12345678* (ensure-vector "vGFO")))
  (is (equalp *btwoc-12345678* (ensure-vector "ALxhTg==")))
  (is (equalp *vector-12345678* (ensure-vector *vector-12345678*))))

(test ensure-vector/random
  (for-all ((i (gen-integer :min 0)))
    (let ((ib (btwoc i))
          (iv (integer-to-octets i)))
      (is (equalp ib (ensure-vector i)))
      (is (equalp ib (ensure-vector (btwoc i))))
      (is (equalp iv (ensure-vector (integer-to-base64-string i))))
      (is (equalp ib (ensure-vector (usb8-array-to-base64-string ib)))))))

(test ensure-vector-length
  (is (equalp #(1 2 3 4 5) (ensure-vector-length #(1 2 3 4 5) 5)))
  (is (equalp #(3 4 5) (ensure-vector-length #(1 2 3 4 5) 3)))
  (is (equalp #(0 0 0 1 2 3 4 5) (ensure-vector-length #(1 2 3 4 5) 8))))

(test new-uri
  (let* ((str "http://example.com/")
         (uri (uri str))
         (nu-str (new-uri str))
         (nu-uri (new-uri uri)))
    (is (uri= uri nu-str))
    (is (uri= uri nu-uri))
    (is (not (eq uri nu-uri)))
    (is (not (eq uri nu-str)))
    (is (not (eq nu-str nu-uri)))))

(test maybe-uri
  (is (null (maybe-uri nil)))
  (is (uri-p (maybe-uri "http://example.com/")))
  (uri= (maybe-uri "http://example.com/") (uri "http://example.com/")))

(test ensure-trailing-slash
  (is (string= "foo/" (ensure-trailing-slash "foo/")))
  (is (string= "foo/" (ensure-trailing-slash "foo"))))
