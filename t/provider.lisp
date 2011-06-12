(in-package #:cl-openid)

(in-suite :cl-openid)

(test check-realm
  ;; A URL matches a realm if:

  ;; * The URL scheme and port of the URL are identical to those in the realm.
  (is-false (check-realm "https://example.com/" "http://example.com/"))
  (is-false (check-realm "http://example.com" "http://example.com:81"))
  (is-false (check-realm "https://example.com:80/" "http://example.com/"))
  (is-false (check-realm "https://example.com:1024/" "http://example.com:2048/"))
  (is-true (check-realm "https://example.com/" "https://example.com/"))
  (is-true (check-realm "https://example.com/foo" "https://example.com/foo"))
  (is-true (check-realm "http://example.com:8000/foo" "http://example.com:8000/foo"))

  ;; * The URL's path is equal to or a sub-directory of the realm's path.
  (is-false (check-realm "http://example.com/foo" "http://example.com/bar"))
  (is-false (check-realm "http://example.com/foo" "http://example.com/"))
  (is-false (check-realm "http://example.com/foo/bar" "http://example.com/foo"))
  (is-true (check-realm "http://example.com/foo" "http://example.com/foo"))
  (is-true (check-realm "http://example.com/foo" "http://example.com/foo/bar"))
  (is-true (check-realm "http://example.com/foo/" "http://example.com/foo/bar"))
  (is-false (check-realm "http://example.com/foo" "http://example.com/foobar"))
  (is-true (check-realm "http://example.com/foo/" "http://example.com/foo/"))
  (is-true (check-realm "http://example.com/foo" "http://example.com/foo/"))

  ;; * Either:
  
  ;;   1. The realm's domain contains the wild-card characters "*.",
  ;;   and the trailing part of the URL's domain is identical to the
  ;;   part of the realm following the "*." wildcard,
  (is-true (check-realm "http://*.example.com/" "http://foo.example.com/"))
  (is-true (check-realm "http://*.example.com/" "http://example.com/"))
  (is-false (check-realm "http://*.example.com/" "http://foo.example.org/"))
  (is-false (check-realm "http://*.example.com/" "http://example.org/"))
  (is-false (check-realm "http://*.example.com" "http://fooexample.com/"))

  ;; or 2. The URL's domain is identical to the realm's domain
  (is-false (check-realm "http://example.com/" "http://example.org/"))
  (is-true (check-realm "http://example.com/" "http://example.com/"))

  ;; Realm MUST NOT contain a URI fragment
  (is-false (check-realm "http://example.com/foo#a" "http://example.com/foo"))
  (is-false (check-realm "http://example.com/foo#a" "http://example.com/foo#a")))


(test unsupported-association-request-handling
  ;; Test how the handle-openid-provider-request function
  ;; handles unsupporeted association requests.
  (flet ((is-assoc-error (&key session-type assoc-type allow-unencrypted-association-p)
           (multiple-value-bind (body status)
               (handle-openid-provider-request (make-instance 'openid-provider)
                                               (make-message :openid.mode "associate"
                                                             :openid.assoc_type assoc-type
                                                             :openid.session_type session-type)
                                               :allow-unencrypted-association-p allow-unencrypted-association-p)
             (declare (ignore body))             
             (is (= 400 status)))))

    ;; correct session types, but bad association type,
    ;; with any value of allow-unencrypted-association-p
    (dolist (allow-unencrypted-association-p '(t nil))
      (is-assoc-error :session-type "DH-SHA1"
                      :assoc-type "bad-assoc-type" 
                      :allow-unencrypted-association-p allow-unencrypted-association-p)
      (is-assoc-error :session-type "DH-SHA256"
                      :assoc-type "bad-assoc-type" 
                      :allow-unencrypted-association-p allow-unencrypted-association-p)      
      (is-assoc-error :session-type ""
                      :assoc-type "bad-assoc-type" 
                      :allow-unencrypted-association-p allow-unencrypted-association-p)
      (is-assoc-error :session-type "no-encription"
                      :assoc-type "bad-assoc-type" 
                      :allow-unencrypted-association-p allow-unencrypted-association-p))

    ;; correct association type, but with bad
    ;; session type, with any value of allow-unencrypted-association-p
    (dolist (allow-unencrypted-association-p '(t nil))
      (is-assoc-error :session-type "bad-session-type"
                      :assoc-type "HMAC-SHA1" 
                      :allow-unencrypted-association-p allow-unencrypted-association-p)
      (is-assoc-error :session-type "bad-session-type"
                      :assoc-type "HMAC-SHA256" 
                      :allow-unencrypted-association-p allow-unencrypted-association-p))

    ;; and finally, when session type is "" or "no-encription",
    ;; with any correct association type, if allow-unencrypted-association-p
    ;; is nil, the requiest should also report an error
    (dolist (assoc-type '("HMAC-SHA1" "HMAC-SHA256"))
      (is-assoc-error :session-type ""
                      :assoc-type assoc-type
                      :allow-unencrypted-association-p nil)
      (is-assoc-error :session-type "no-encription"
                      :assoc-type assoc-type
                      :allow-unencrypted-association-p nil))))

