(in-package #:cl-openid)

(in-suite :cl-openid)

(test parse-kv
  (dolist (test-case '(("mode:error
error:This is an example message
"
                        ("mode" . "error") ("error" . "This is an example message"))
                       ("")))
    (is (equal (parse-kv (string-to-utf-8-bytes (car test-case)))
               (cdr test-case)))))

(let ((gen-character (gen-character)))
  (defun gen-k-char ()
    (loop
       for char = (funcall gen-character)
       while (member char '(#\: #\Newline))
       finally (return char)))
  (defun gen-v-char ()
    (loop
       for char = (funcall gen-character)
       while (member char '(#\Newline))
       finally (return char))))


(defun gen-kv-alist (&optional (length (gen-integer :min 1 :max 100)))  
  (loop
     with gen-k = (gen-string :elements #'gen-k-char)
     with gen-v = (gen-string :elements #'gen-v-char)
     for i from 1 to (funcall length)
     for k = (funcall gen-k)
     for v = (funcall gen-v)
     collect (cons k v)))

(defun kv-alist-to-kv (alist)
  (string-to-utf-8-bytes
   (apply #'concatenate 'string
          (loop for (k . v) in alist
             collect k
             collect ":"
             collect v
             collect '(#\Newline)))))

(test parse-kv/random
  (for-all ((kv-alist #'gen-kv-alist))
    (is (equal kv-alist (parse-kv (kv-alist-to-kv kv-alist))))))

(test session-digest-type
  (is (eq :sha1 (session-digest-type "DH-SHA1")))
  (is (eq :sha256 (session-digest-type "DH-SHA256")))
  (is (eq nil (session-digest-type "no-encryption")))
  (is (eq nil (session-digest-type "")))
  (for-all ((s (gen-string)))
    (if (member s '("DH-SHA1" "DH-SHA256" "no-encryption" "")
                :test #'string=)
        (pass)                          ; already tested
        (signals error (session-digest-type s)))))
