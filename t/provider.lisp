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


;; Test openid-provider; the implementations of generic 
;; functions which should be redefined by a derived class
;; are slots here, so that we don't need to define new
;; class for every test case where we need to hook into 
;; the functions.
(defclass test-openid-provider (openid-provider)
  ((handle-checkid-setup-impl :type (or function null)
                              :initarg :handle-checkid-setup-impl
                              :initform nil)
   (handle-checkid-immediate-impl :type (or function null) 
                                  :initarg :handle-checkid-immediate-impl
                                  :initform nil)))

(defmethod handle-checkid-setup ((op test-openid-provider) message)
  (with-slots ((impl handle-checkid-setup-impl)) op
    (if impl
        (funcall impl op message)
        (call-next-method))))

(defmethod handle-checkid-immediate ((op test-openid-provider) message)
  (with-slots ((impl handle-checkid-immediate-impl)) op
    (if impl
        (funcall impl op message)
        (call-next-method))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; Some utils code
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
             
(defun split (char string)
    "Returns a list of substrings of string
divided by ONE character CHAR each.
Note: Two consecutive CHARs will be seen as
if there were an empty string between them."
    (loop for i = 0 then (1+ j)
          as j = (position char string :start i)
          collect (subseq string i j)
          while j))

;; -------------------------------------------------------------------------- ;;
;; UrlDecoding
;;
;; copy/pasted from hunchentoot.
;; It's bad we don't have a reusable library for just url-decoding/encoding.
;; Maybe move it to a separate library some day...
;; call the main functions encode-uri-component decode-uri-component then.
;; -------------------------------------------------------------------------- ;;

(defmacro upgrade-vector (vector new-type &key converter)
  "Returns a vector with the same length and the same elements as
VECTOR \(a variable holding a vector) but having element type
NEW-TYPE.  If CONVERTER is not NIL, it should designate a function
which will be applied to each element of VECTOR before the result is
stored in the new vector.  The resulting vector will have a fill
pointer set to its end.

The macro also uses SETQ to store the new vector in VECTOR."
  `(setq ,vector
         (loop with length = (length ,vector)
               with new-vector = (make-array length
                                             :element-type ,new-type
                                             :fill-pointer length)
               for i below length
               do (setf (aref new-vector i) ,(if converter
                                               `(funcall ,converter (aref ,vector i))
                                               `(aref ,vector i)))
               finally (return new-vector))))

(defun url-decode (string &optional (external-format :utf-8))
  "Decodes a URL-encoded STRING which is assumed to be encoded using
the external format EXTERNAL-FORMAT."
  (when (zerop (length string))
    (return-from url-decode ""))
  (let ((vector (make-array (length string) :element-type '(unsigned-byte 8) :fill-pointer 0))
        (i 0)
        unicodep)
    (loop
      (unless (< i (length string))
        (return))
      (let ((char (aref string i)))
       (labels ((decode-hex (length)
                  (prog1
                      (parse-integer string :start i :end (+ i length) :radix 16)
                    (incf i length)))
                (push-integer (integer)
                  (vector-push integer vector))
                (peek ()
                  (aref string i))
                (advance ()
                  (setq char (peek))
                  (incf i)))
         (cond
          ((char= #\% char)
           (advance)
           (cond
            ((char= #\u (peek))
             (unless unicodep
               (setq unicodep t)
               (upgrade-vector vector '(integer 0 65535)))
             (advance)
             (push-integer (decode-hex 4)))
            (t
             (push-integer (decode-hex 2)))))
          (t
           (push-integer (char-code (case char
                                      ((#\+) #\Space)
                                      (otherwise char))))
           (advance))))))
    (cond (unicodep
           (upgrade-vector vector 'character :converter #'code-char))
          (t (flex:octets-to-string vector :external-format external-format)))))


;; -------------------------------------------------------------------------------- ;;
;; end of UrlDecoding
;; -------------------------------------------------------------------------------- ;;

;; Helper function to parse key-vals of the URL parameters.
;; Again, copy/pasted from hunchentoot.
(defun form-url-encoded-list-to-alist (form-url-encoded-list
                                       &optional (external-format :utf-8))
  "Converts a list FORM-URL-ENCODED-LIST of name/value pairs into an
alist.  Both names and values are url-decoded while doing this.
FORM-URL-ENCODED-LIST is something like (\"key=value\" \"key2=value2\")."
  (mapcar #'(lambda (entry)
              (destructuring-bind (name &optional value)
                  ;;(split "=" entry :limit 2) ;; it's the original hunchentoot code
                  ;; but our SPLIT is simpler, there is no :LIMIT 2 argument
                  ;; (and we are not copy/pasting the SPLIT from hunchentoot
                  ;; because we don't want to depend on ppcre
                  (split #\= entry)
                (cons (string-trim " " (url-decode name external-format))
                      (url-decode (or value "") external-format))))
          form-url-encoded-list))

(defun uri-query-to-params-alist (uri-query-string)
  (form-url-encoded-list-to-alist (split #\& uri-query-string)))

(defun uri-params-alist (uri)
  "URI may be as string or PURI:URI"
  (uri-query-to-params-alist (puri:uri-query (puri:uri uri))))

(defun uri-param (uri param-name)
  "URI may be a string or PURI:URI"
  (cdr (assoc param-name (uri-params-alist uri)
              :test #'string=)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; end of the utils
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(test user-setup-url
  (let* (;; make a customized instance of the TEST-OPENID-PROVIDER
         ;; which returns a special value from handle-checkid-setup.
         (op (make-instance 'test-openid-provider 
                            :endpoint-uri "http://test-endpoint-uri.com/"
                            :handle-checkid-setup-impl (lambda (&rest ignored)
                                                         (declare (ignore ignored))
                                                         (values "handle-checkid-setup-called" 200)))))
    
    ;; Now request checkid-immediate from that provider
    ;; receive negative response and retrieve 
    ;; the openid.user_setup_url response parameter.
    ;;
    ;; This response parameter should be a valid checkid_setup request
    ;; to the same provider.
    ;;
    ;; Test it by querying the provider and ensuring the 
    ;; handle-openid-provider-requeest returns the value we return 
    ;; from handle-checkid-setup, which means our checkid-setup was called.
    (let ((claimed-id "test-claimed-id")
          (op-local-id "test-op-local-id")
          (return-to "test-return-to")
          (protocol-version-major 1)
          (realm "test-realm"))
      (let* ((msg (make-message
                   :openid.mode "checkid_immediate"
                   :openid.claimed_id claimed-id
                   :openid.identity (or op-local-id claimed-id) 
                   :openid.return_to return-to
                   (if (= 2 protocol-version-major)
                       :openid.realm ; OpenID 1.x compat: trust_root instead of realm
                       :openid.trust_root) realm))
             (reply-uri (handle-openid-provider-request op 
                                                        msg 
                                                        :allow-unencrypted-association-p t))
             (setup-url (uri-param reply-uri "openid.user_setup_url"))
             (new-request-msg (uri-params-alist setup-url)))
        
        (is (string= "handle-checkid-setup-called"
                     (cl-openid:handle-openid-provider-request op
                                                               new-request-msg
                                                               :allow-unencrypted-association-p t)))))))
