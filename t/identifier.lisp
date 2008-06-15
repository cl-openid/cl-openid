(in-package #:cl-openid)

(in-suite :cl-openid)

(defparameter +gen-path-element+
  (gen-string :elements (gen-character :alphanumericp t
                                       :code (gen-integer :min 16 :max 65535))
              :length (gen-integer :min 1 :max 20)))

(defun insert-dots (initial-list
                    &key
                    (p-dot 1/2)
                    (p-ddot 1/4)
                    (p-empty 1/4)
                    (max-ddot 10)
                    (random-elt +gen-path-element+))
  "Return a list that, after traversing, should be identical to INITIAL-LIST."
  (let* ((rv (list 'junk))
         (rv-tail (last rv)))
    (labels ((do-collect (elt)
               (setf (rest rv-tail) (list elt)
                     rv-tail (rest rv-tail)))
             (collect (elt)
               (cond
                 ((< (random 1.0) p-empty) (collect ""))
                 ((< (random 1.0) p-dot) (collect "."))
                 ((< (random 1.0) p-ddot)
                  (let ((nddot (random max-ddot)))
                    (dotimes (i nddot)
                      (do-collect (funcall random-elt)))
                    (dotimes (i nddot)
                      (do-collect "..")))))
               (do-collect elt)))
      (when (< (random 1.0) p-ddot)
        (let ((nddot (random max-ddot)))
          (dotimes (i nddot)
            (collect (funcall random-elt)))
          (dotimes (i nddot)
            (collect ".."))
          (dotimes (i (random (- max-ddot nddot)))
            (collect ".."))))
      (dolist (elt initial-list)
        (collect elt)))
    (rest rv)))

(test remove-dot-segments
  (dolist (path '(("foo" "bar" "baz")
                  ("foo" "bar" "baz")
                  ("foo" "." "bar" "baz")
                  ("foo" "bar" "." "." "baz")
                  ("foo" "bar" ".." "bar" "baz")
                  ("bar" ".." ".." "foo" "bar" "baz")
                  ("foo" "bar" "quux" "xyzzy" ".." ".." "baz")
                  (".." ".." "." "foo" "bar" "baz")))
    ;; no trailing slash
    (is (equalp '(junk "foo" "bar" "baz")
                (remove-dot-segments (cons 'junk path))))
    ;; with trailing slash
    (dolist (appendix '(("") (".") ("" "") ("." "") ("." ".") ("" ".")))
      (is (equalp '(junk "foo" "bar" "baz" "")
                  (remove-dot-segments (append (cons 'junk path) appendix)))))))

(test remove-dot-segments/random
  (for-all ((original-list (gen-list :elements +gen-path-element+)))
    ;; no trailing slash
    (is (equalp (cons 'junk original-list)
                (remove-dot-segments
                 (cons 'junk (insert-dots original-list)))))
    ;; with trailing slash
    (dolist (appendix '(("") (".") ("" "") ("." "") ("." ".") ("" ".")))
      (is (equalp (append (cons 'junk original-list) '(""))
                  (remove-dot-segments (append (cons 'junk (insert-dots original-list)) appendix)))))))

(test normalize-identifier
  (signals error (normalize-identifier "xri://=test"))
  (signals error (normalize-identifier "=test"))
  (signals error (normalize-identifier "http://example.com/nonexistent"))
  (signals error (normalize-identifier "http://test.invalid/"))
  (dolist (test-case '(("example.com" . "http://example.com/")

                       ("http://example.com" . "http://example.com/")
                       ("http://example.com/" . "http://example.com/")
                       #+SSL ("https://example.com/" . "https://example.com/")
                       
                       ("http://common-lisp.net/project/cl-openid/index.shtml" . "http://common-lisp.net/project/cl-openid/index.shtml")
                       ("http://common-lisp.net/project/cl-openid/index.shtml/" . "http://common-lisp.net/project/cl-openid/index.shtml/")

                       ("http://Common-Lisp.NET/../t/../project/./%63l-openi%64/./index.shtml" . "http://common-lisp.net/project/cl-openid/index.shtml")))
    (is (string= (princ-to-string (cdr (assoc :claimed-id (normalize-identifier (car test-case)))))
                 (cdr test-case)))))

(test n-remove-entities
  (dolist (test-case '(("sanity test" . "sanity test")

                       ("foo &lt; bar" . "foo < bar")
                       ("foo &gt; bar" . "foo > bar")
                       ("foo &amp; bar" . "foo & bar")
                       ("foo &quot;bar&quot;" . "foo \"bar\"")
                       ("&lt;&amp;&quot;&gt;" . "<&\">")
                       ("&amp;&gt;&lt;" . "&><")

                       ("in&sanity <test>" . "in&sanity <test>")
                       ("in&sane &amp; &quot;b0rken<>&quot" . "in&sane & \"b0rken<>&quot") ; Final &quot intentionally lacks a semicolon, shall not pass.
                       ))
    (is (string= (n-remove-entities (copy-seq (car test-case)))
                 (cdr test-case)))))

(test n-remove-entities/random
  (for-all ((unquoted (gen-string :elements (gen-one-element #\Space #\< #\> #\" #\& #\- #\a #\b #\c #\d #\e #\f #\g #\h))))
    (is (string= unquoted (n-remove-entities (xmls:toxml unquoted))))))

(defun alist-contains (alist reference)
  (every #'(lambda (item)
             (equal (cdr item)
                    (cdr (assoc (car item) alist))))
         reference))

(test perform-html-discovery
  (dolist (test-case '(("sanity test" (:op-endpoint-url) (:op-local-identifier) (:v1.op-endpoint-url) (:v1.op-local-identifier) (:x-xrds-location))

                       ;; single tags
                       ("<link rel=\"openid2.provider\" href=\"http://example.com/\">"
                        (:op-endpoint-url . "http://example.com/") (:op-local-identifier) (:v1.op-endpoint-url) (:v1.op-local-identifier) (:x-xrds-location))
                       ("<link rel=\"openid2.local_id\" href=\"http://example.com/\">"
                        (:op-endpoint-url) (:op-local-identifier  . "http://example.com/") (:v1.op-endpoint-url) (:v1.op-local-identifier) (:x-xrds-location))
                       ("<link rel=\"openid.server\" href=\"http://example.com/\">"
                        (:op-endpoint-url) (:op-local-identifier) (:v1.op-endpoint-url . "http://example.com/") (:v1.op-local-identifier) (:x-xrds-location))
                       ("<link rel=\"openid.delegate\" href=\"http://example.com/\">"
                        (:op-endpoint-url) (:op-local-identifier) (:v1.op-endpoint-url) (:v1.op-local-identifier . "http://example.com/") (:x-xrds-location))
                       ("<meta http-equiv=\"X-XRDS-Location\" content=\"http://example.com/\">"
                        (:op-endpoint-url) (:op-local-identifier) (:v1.op-endpoint-url) (:v1.op-local-identifier) (:x-xrds-location . "http://example.com/"))

                       ;; combo
                       ("<link rel=\"openid2.provider\" href=\"http://example.com/ep\"> <link rel=\"openid2.local_id\" href=\"http://example.com/oploc\"> <link rel=\"openid.server\" href=\"http://example.com/epv1\"> <link rel=\"openid.delegate\" href=\"http://example.com/oplocv1\"> <meta http-equiv=\"X-XRDS-Location\" content=\"http://example.com/xrds\">"
                        (:op-endpoint-url . "http://example.com/ep")
                        (:op-local-identifier . "http://example.com/oploc")
                        (:v1.op-endpoint-url . "http://example.com/epv1")
                        (:v1.op-local-identifier . "http://example.com/oplocv1")
                        (:x-xrds-location . "http://example.com/xrds"))))
    (is (alist-contains (perform-html-discovery () (car test-case))
                        (cdr test-case)))))

(test perform-xrds-discovery
  (labels ((xrds (xml alist &rest rest)
             (cons (cons (format nil "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<xrds:XRDS xmlns:xrds=\"xri://$xrds\" xmlns=\"xri://$xrd*($v*2.0)\"
           xmlns:openid=\"http://openid.net/xmlns/1.0\"><XRD>
~A</XRD></xrds:XRDS>" xml) alist)
                   (when rest
                     (apply #'xrds rest)))))

    (dolist (test-case (xrds
                        ;; Sanity check
                        "" '((:op-endpoint-url) (:op-local-identifier) (:v1.op-endpoint-url) (:v1.op-local-identifier) (:v1.type))

                        ;; Simple endpoint 2.0 (Yahoo)
                        "<Service>
<Type>http://specs.openid.net/auth/2.0/server</Type>
<URI>http://example.com/</URI>
</Service>"
                        '((:op-endpoint-url . "http://example.com/") (:op-local-identifier) (:v1.op-endpoint-url) (:v1.op-local-identifier) (:v1.type))

                        ;; Simple OP-local ID 2.0 (example in OpenID 2.0 standard, Appendix A.3
                        "<Service xmlns=\"xri://$xrd*($v*2.0)\">
<Type>http://specs.openid.net/auth/2.0/signon</Type>
<URI>https://www.exampleprovider.com/endpoint/</URI>
<LocalID>https://exampleuser.exampleprovider.com/</LocalID>
</Service>"
                        '((:op-endpoint-url . "https://www.exampleprovider.com/endpoint/") (:op-local-identifier . "https://exampleuser.exampleprovider.com/") (:v1.op-endpoint-url) (:v1.op-local-identifier) (:v1.type))

                        ;; Simple endpoint 1.0
                        "<Service>
<Type>http://openid.net/server/1.0</Type>
<URI>http://example.com/endpoint/</URI>
</Service>"
                        '((:v1.type . "http://openid.net/server/1.0")
                          (:v1.op-endpoint-url . "http://example.com/endpoint/")
                          (:v1.op-local-identifier) (:op-endpoint-url) (:op-local-identifier))

                        ;; type variants
                        "<Service>
<Type>http://openid.net/signon/1.0</Type>
<URI>http://example.com/endpoint/</URI>
</Service>"
                        '((:v1.type . "http://openid.net/signon/1.0")
                          (:v1.op-endpoint-url . "http://example.com/endpoint/")
                          (:v1.op-local-identifier) (:op-endpoint-url) (:op-local-identifier))
 
                        "<Service>
<Type>http://openid.net/server/1.1</Type>
<URI>http://example.com/endpoint/</URI>
</Service>"
                        '((:v1.type . "http://openid.net/server/1.1")
                          (:v1.op-endpoint-url . "http://example.com/endpoint/")
                          (:v1.op-local-identifier) (:op-endpoint-url) (:op-local-identifier))

                        "<Service>
<Type>http://openid.net/signon/1.1</Type>
<URI>http://example.com/endpoint/</URI>
</Service>"
                        '((:v1.type . "http://openid.net/signon/1.1")
                          (:v1.op-endpoint-url . "http://example.com/endpoint/")
                          (:v1.op-local-identifier) (:op-endpoint-url) (:op-local-identifier))                        

                        ;; Simple OP-local ID 1.0
                        "<Service priority=\"20\">
<Type>http://openid.net/server/1.0</Type>
<URI>http://example.com/endpoint/</URI>
<openid:Delegate>http://example.com/oplocal/</openid:Delegate>
</Service>"
                        '((:v1.type . "http://openid.net/server/1.0")
                          (:v1.op-endpoint-url . "http://example.com/endpoint/")
                          (:v1.op-local-identifier . "http://example.com/oplocal/")
                          (:op-endpoint-url) (:op-local-identifier))

                        ;; Combo example from Wikipedia
                        "<Service>
      <!-- XRI resolution service -->
      <ProviderID>xri://=!F83.62B1.44F.2813</ProviderID>
      <Type>xri://$res*auth*($v*2.0)</Type>
      <MediaType>application/xrds+xml</MediaType>
      <URI priority=\"10\">http://resolve.example.com</URI>
      <URI priority=\"15\">http://resolve2.example.com</URI>
      <URI>https://resolve.example.com</URI>
    </Service>
    <!-- OpenID 2.0 login service -->
    <Service priority=\"10\">
      <Type>http://specs.openid.net/auth/2.0/signon</Type>
      <URI>http://www.myopenid.com/server</URI>
      <LocalID>http://example.myopenid.com/</LocalID>
    </Service>
    <!-- OpenID 1.0 login service -->
    <Service priority=\"20\">
      <Type>http://openid.net/server/1.0</Type>
      <URI>http://www.livejournal.com/openid/server.bml</URI>
      <openid:Delegate>http://www.livejournal.com/users/example/</openid:Delegate>
    </Service>
    <!-- untyped service for access to files of media type JPEG -->
    <Service priority=\"10\">
      <Type match=\"null\" />
      <Path select=\"true\">/media/pictures</Path>
      <MediaType select=\"true\">image/jpeg</MediaType>
      <URI append=\"path\" >http://pictures.example.com</URI>
    </Service>"
                        '((:v1.type . "http://openid.net/server/1.0")
                          (:v1.op-local-identifier . "http://www.livejournal.com/users/example/")
                          (:v1.op-endpoint-url . "http://www.livejournal.com/openid/server.bml")
                          (:op-local-identifier . "http://example.myopenid.com/")
                          (:op-endpoint-url . "http://www.myopenid.com/server"))

                        ;; Priority / 1.0, openid.pl
                        "<Service priority=\"10\">
      <Type>http://openid.net/signon/1.1</Type>
      <Type>http://openid.net/sreg/1.0</Type>
      <URI>http://example.com/server</URI>
    </Service>

    <Service priority=\"20\">
      <Type>http://openid.net/signon/1.0</Type>
      <Type>http://openid.net/sreg/1.0</Type>
      <URI>http://example.com/server</URI>
    </Service>"
                        '((:v1.type . "http://openid.net/signon/1.1")
                          (:v1.op-endpoint-url . "http://example.com/server"))

                        ;; Combo 1.0/2.0 in single Service tag (vinismo.com Wiki)
                        "<Service priority=\"0\">
    <URI>http://example.com/endpoint/</URI>
    <Type>http://openid.net/signon/1.0</Type>
    <Type>http://openid.net/sreg/1.0</Type>
    <Type>http://specs.openid.net/auth/2.0/signon</Type>
  </Service>"
                        '((:v1.op-endpoint-url . "http://example.com/endpoint/")
                          (:v1.type . "http://openid.net/signon/1.0")
                          (:op-endpoint-url . "http://example.com/endpoint/")
                          (:v1.op-endpoint-url . "http://example.com/endpoint/"))
                        ))

      (is (alist-contains (perform-xrds-discovery () (car test-case))
                          (cdr test-case))))))

