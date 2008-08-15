(in-package #:cl-openid)

(in-suite :cl-openid)

(test in-ns
  (let ((sentinel (gensym)))
    (is (equal `(("openid.ns" . "http://specs.openid.net/auth/2.0") . ,sentinel)
               (in-ns sentinel)))))

(test message-field
  (let ((message '(("foo" . 1)
                   ("bar" . 2)
                   ("baz" . 3))))
    (is (eql 1 (message-field message "foo")))
    (is (eql 3 (message-field message "baz")))
    (is (null (message-field message "xyzzy")))))

(test message-v2-p
  (let ((message '(("openid.foo" . 1)
                   ("openid.bar" . 2)
                   ("openid.baz" . 3))))
    (is (null (message-v2-p message)))
    (is-true (message-v2-p (in-ns message)))))

(test make-message
  (is (equal `(("string" . "bar")
               ("symbol" . ,(string 'foo))
               ("integer" . "123")
               ("uri" . "http://example.com/foo")
               ("octet-vector" . ,(usb8-array-to-base64-string #(1 2 3 4)))
               ("dot.in.name" . "works"))
             (make-message :string "bar"
                           :symbol 'foo
                           :integer 123
                           :uri (uri "http://example.com/foo")
                           :octet-vector (make-array 4
                                                     :element-type '(unsigned-byte 8)
                                                     :initial-contents '(1 2 3 4))
                           :dot.in.name "works"))))

(defun alist= (alist1 alist2)
  (and (null (set-exclusive-or (mapcar #'car alist1)
                               (mapcar #'car alist2)
                               :test #'equal))
       (every #'(lambda (item)
                  (equal item
                         (assoc (car item) alist2
                                :test #'equal)))
              alist1)))

(test copy-message
  (let ((message '(("string" . "bar")
                   ("integer" . "123")
                   ("uri" . "http://example.com/foo")
                   ("dot.in.name" . "works"))))
    (is (alist= (copy-message message
                              :uri "http://example.com/bar"
                              :new-field "is also there")
                '(("string" . "bar")
                  ("integer" . "123")
                  ("uri" . "http://example.com/bar")
                  ("dot.in.name" . "works")
                  ("new-field" . "is also there"))))))


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

(test encode-kv
  (dolist (test-case '(("mode:error
error:This is an example message
"
                        ("mode" . "error") ("error" . "This is an example message"))
                       ("")))
    (is (equalp (string-to-utf-8-bytes (first test-case))
                (encode-kv (rest test-case))))))

(test indirect-request-uri
  (let ((message '(("foo" . "1")
                   ("bar" . "2")
                   ("baz" . "3"))))
    (dolist (test-case `(("http://www.example.com/" ,message "http://www.example.com/?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&foo=1&bar=2&baz=3")
                         ("http://www.example.com/ep" ,message "http://www.example.com/ep?openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&foo=1&bar=2&baz=3")
                         ("http://www.example.com/ep/?test=query-string" ,message "http://www.example.com/ep/?test=query-string&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&foo=1&bar=2&baz=3")))
      (is (uri= (uri (third test-case))
                (indirect-request-uri (first test-case) (second test-case)))))))

(test indirect-response-uri
  (let ((message '(("foo" . "1")
                   ("bar" . "2")
                   ("baz" . "3"))))
    (dolist (test-case `(("http://www.example.com/" ,message "http://www.example.com/?foo=1&bar=2&baz=3")
                         ("http://www.example.com/ep" ,message "http://www.example.com/ep?foo=1&bar=2&baz=3")
                         ("http://www.example.com/ep/?test=query-string" ,message "http://www.example.com/ep/?test=query-string&foo=1&bar=2&baz=3")))
      (is (uri= (uri (third test-case))
                (indirect-response-uri (first test-case) (second test-case)))))))

