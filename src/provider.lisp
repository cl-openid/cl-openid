(in-package #:cl-openid)

;; (use-package :defclass-star)
;; (setf *accessor-name-transformer* #'(lambda (n d) (declare (ignore d)) n))
#+macroexpand-and-paste
(defclass* openid-provider ()
  ((endpoint-uri :documentation "Provider endpoint URI")
   (associations (make-hash-table :test #'equal)
                 :documentation "OP's associations.")
   (associations-lock (make-lock)))
  (:documentation "OpenID Provider server abstract class.

This class should be subclassed, and specialized methods should be
provided at least for HANDLE-CHECKID-SETUP (preferably also for
HANDLE-CHECKID-IMMEDIATE)."))

(defclass openid-provider ()
  ((endpoint-uri :accessor endpoint-uri :initarg :endpoint-uri
                    :documentation "Provider endpoint URI")
   (associations :initform (make-hash-table :test #'equal)
                 :accessor associations :initarg :associations
                 :documentation "OP's associations.")
   (associations-lock :initform (make-lock)
                      :accessor associations-lock :initarg :associations-lock))
  (:documentation "OpenID Provider server abstract class.

This class should be subclassed, and specialized methods should be
provided at least for HANDLE-CHECKID-SETUP (preferably also for
HANDLE-CHECKID-IMMEDIATE)."))

(defvar *nonce-counter* 0
  "Counter for nonce generation")

(defun nonce ()
  (multiple-value-bind (sec min hr day mon year wday dst tz)
      (decode-universal-time (get-universal-time) 0)
    (declare (ignore wday dst tz))
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ~A"
            year mon day hr min sec
            (integer-to-base64-string (incf *nonce-counter*)))))

(defconstant +indirect-response-code+ 303
  "HTTP code recommented to use for indirect responses sent via HTTP redirect.")

(defun indirect-response (return-to message)
  "Return indirect response (URI as body +INDIRECT-RESPONSE-CODE+ as the second value)."
  (values (indirect-message-uri return-to message)
          +indirect-response-code+))

(defun direct-error-response (err &key contact reference message)
  "Return error direct response (key-value-encoded error message as
body, 400 Error code as second value)."
  (values (encode-kv (error-response-message err
                                             :contact contact
                                             :reference reference
                                             :message message))
          400))

(defun direct-response (message)
  "Return direct response (key-value-encoded MESSAGE as body, no second value)."
  (encode-kv message))

(define-condition indirect-error (error)
  ((reason :initarg :reason :reader reason
           :documentation "Textual error description.")
   (return-to-uri :initform nil :initarg :return-to-uri :reader return-to-uri
                  :documentation "return_to address to direct indirect error message to."))
  (:report (lambda (e s)
             (princ (reason e) s)))
  (:documentation "Error occured during OpenID chekid_setup or checkid_immediate handling.

This condition is handled by HANDLE-OPENID-PROVIDER-REQUEST and, if it
occurs, indirect error response is directed to user."))

(defmacro with-indirect-error-handler (&body body)
  "Handle INDIRECT-ERROR in BODY.

When INDIRECT-ERROR is signaled, immediately return indirect error response."
  (let ((block-name (gensym "INDIRECT-ERROR-HANDLER-BLOCK")))
    `(block ,block-name
       (handler-bind ((indirect-error
                       #'(lambda (e)
                           (return-from ,block-name
                             (if (return-to-uri e)
                                 (indirect-response (return-to-uri e)
                                                    (in-ns (make-message :openid.mode "error"
                                                                         :openid.error (princ-to-string e))))
                                 (values (princ-to-string e) 400))))))
         ,@body))))

(defun signal-indirect-error (message reason &rest args)
  "Signal INDIRECT-ERROR condition for MESSAGE, effectively returning indirect error reply from WITH-INDIRECT-ERROR-HANDLER.

REASON is textual error message format string, with ARGS being its
arguments."
  (error 'indirect-error
         :reason (format nil reason args)
         :return-to-uri (message-field message "openid.return_to")))

;;; Positive assertion generation
(defun successful-response-message (op message)
  (gc-associations op)
  (let* ((assoc (with-lock-held ((associations-lock op))
                  (or (gethash (message-field message "openid.assoc_handle")
                               (associations op))
                      (let ((new-association (make-association
                                              :hmac-digest (if (message-v2-p message)
                                                               :sha256
                                                               :sha1))))
                        (setf (gethash (association-handle new-association) (associations op))
                              new-association)
                        new-association))))
         (rv (make-message :openid.mode "id_res"
                           :openid.op_endpoint (when (message-v2-p message)
                                                 (endpoint-uri op))
                           :openid.claimed_id (message-field message "openid.identity")
                           :openid.identity (message-field message "openid.identity")
                           :openid.return_to (message-field message "openid.return_to")
                           :openid.response_nonce (nonce)
                           :openid.assoc_handle (association-handle assoc)
                           :openid.signed "op_endpoint,identity,claimed_id,return_to,assoc_handle,response_nonce"
                           ;; FIXME:invalidate_handle
                           )))
    (in-ns (signed assoc rv))))

(defun successful-response-uri (op auth-request-message)
  "Returns the URI of the Relying Party to redirect the user's browser
to. The URI parameters tell the Relying Party that the authentication 
was successful. AUTH-REQUEST-MESSAGE should be the oritinal OpenID 
authentication request message that was received from the Relying Party 
previously and passed to the HANDLE-CHECKID-SETUP."
  (princ-to-string
   (indirect-response (message-field auth-request-message "openid.return_to")
                      (successful-response-message op auth-request-message))))

;;; Setup needed message generation.

;; For backward compatibility with OpenID 1.1
;; we need to provide the openid.user_setup_url response
;; parameter when replying to a failed immediate
;; authentication requests.
;;
;; See OpenID Authentication 1.1, Sections 
;; 4.2.2.2. Sent on Failed Assertion and 4.2.3. Extra Notes 
;; for the description of this response parameter. 
;; And OpenID Authentication 2.0 - Final, 
;; Section 14.2. Implementing OpenID Authentication 1.1 Compatibility 
;; requiring us to implement it.
;;
;; In our implementation the openid.user_setup_url is just an URI
;; representing checkid_setup authentication request to the
;; same provider.
(defun user-setup-url (op message)
  "Returns the value to be passed in the openid.user_setup_url 
parameter of a response to a failed immediate authentication request. 
OP is the OpenID Provider. MESSAGE is the original authentication 
request. In case the MESSAGE is a request of OpenID version 2, 
returns NIL."
  (declare (ignore op))
  (when (not (message-v2-p message))
    (indirect-message-uri (endpoint-uri op)
                          (copy-message message :openid.mode "checkid_setup"))))

(define-constant +setup-needed-response-message+
    (in-ns (make-message :openid.mode "setup_needed")))

(defun setup-needed-response-message (op message)
  (copy-message +setup-needed-response-message+
                :openid.user_setup_url (user-setup-url op message)))

(defun setup-needed-response (op message)
  "Send setup_needed (immediate authentication failure) response to MESSAGE from OP."
  (indirect-response (message-field message "openid.return_to")
                     (setup-needed-response-message op message)))

;;; Negative assertion generation
(define-constant +cancel-response-message+
    (in-ns (make-message :openid.mode "cancel")))

(defun cancel-response-uri (op auth-request-message)
  "Returns the URI of the Relying Party to redirect the user's browser
to. The URI parameters tell the Relying Party that the authentication 
failed. AUTH-REQUEST-MESSAGE should be the oritinal OpenID 
authentication request message that was received from the Relying Party 
previously and passed to the HANDLE-CHECKID-SETUP."
  (declare (ignore op))
  (princ-to-string
   (indirect-response (message-field message "openid.return_to")
                      +cancel-response-message+)))


(defgeneric handle-checkid-setup (op message)
  (:documentation "Handles checkid_setup requests.

This generic should be specialized on concrete Provider classes to
perform login checks with user dialogue, that would (possibly
after some HTTP request-response cycles) end by redirecting the 
user's browser either to SUCCESSFUL-RESPONSE-URI, or to 
CANCEL-RESPONSE-URI.

This generic is called by HANDLE-OPENID-PROVIDER-REQUEST.
The value(s) returned by this function are then returned by
HANDLE-OPENID-PROVIDER-REQUEST.

Default method just returns (VALUES CANSEL-RESPONSE-URI +INDIRECT-RESPONSE-CODE+).")
  (:method (op message)
    (if (message-field message "openid.return_to")
        (values (cancel-response-uri op message) +indirect-response-code+)
        (values "CANCEL" 400))))

(defgeneric handle-checkid-immediate (op message)
  (:documentation "Handles checkid_immediate requests.

This generic should be specialized on concrete Provider classes to
perform immediate login checks on MESSAGE. It should return at once,
either true value (to indicate successful login), or NIL (to indicate
immediate login failure).")
  (:method (op message)
    "Always fail."
    (declare (ignore op message))
    nil))

;;; Realm checking: 9.2.  Realms
(defun check-realm (realm uri)
  "Check URI against REALM."

  (setf realm (uri realm)
        uri (uri uri))

  ;; A URL matches a realm if:
  (and
   (null (uri-fragment realm))          ; Additional requirement on realm
   
   ;; The URL scheme and port of the URL are identical to those in the realm.
   (eq (uri-scheme realm) (uri-scheme uri))
   (eql (uri-port realm) (uri-port uri))

   ;; The URL's path is equal to or a sub-directory of the realm's path.
   (if (< (length (uri-path realm)) (length (uri-path uri))) ; Subdir.
       (or (null (uri-path realm))      ; Any dir is subdir of root.
           (let ((realm-path (ensure-trailing-slash (uri-path realm))))
             (string= realm-path (subseq (uri-path uri) 0 (length realm-path)))))
       (string= (uri-path uri) (uri-path realm)))

   ;; Either:
   (if (string= "*." (subseq (uri-host realm) 0 2)) ; 1. The realm's
                                                    ; domain contains
                                                    ; the wild-card
                                                    ; characters "*.",

       ;; and the trailing part of the URL's domain is identical to the
       ;; part of the realm following the "*." wildcard,
       (if (= (length (uri-host uri)) (- (length (uri-host realm)) 2))
           (string-equal (uri-host uri) (subseq (uri-host realm) 2)) ; root domain (e.g. example.com vs *.example.com)
           (string-equal (subseq (uri-host realm) 1) ; subdomain (e.g. foo.example.com vs *.example.com)
                         (subseq (uri-host uri)
                                 (- (length (uri-host uri))
                                    (1- (length (uri-host realm)))))))

       ;; or 2. The URL's domain is identical to the realm's domain
       (string-equal (uri-host realm) (uri-host uri)))))

(defun handle-openid-provider-request (op message &key allow-unencrypted-association-p
                                       &aux (v1-compat (not (message-v2-p message))))
  "Handle request MESSAGE for OpenID Provider instance OP.

ALLOW-UNENCRYPTED-ASSOCIATION-P specifies whether it is allowable
to use unencrypted association method. Set it to NIL unless your
OP endopoint uses HTTPS. See OpenID Authentication 2.0 - Final, section 
8.4.1. No-Encryption Association Sessions
(http://openid.net/specs/openid-authentication-2_0.html#assoc_sess_types).

Returns two values: the first is body, and the second is an HTTP 
status code.

On HTTP redirections (the second value between 300 and 399 inclusive), 
the primary returned value will be an URI to redirect the user to."
  (string-case (message-field message "openid.mode")
    ("associate"
     (gc-associations op)
     (handler-case
         (values
          (encode-kv                         ; Direct response
           (string-case (message-field message "openid.session_type")
             (("DH-SHA1" "DH-SHA256")
              (let ((private (secure-random:number +dh-prime+))
                    (association (make-association :association-type (or (message-field message "openid.assoc_type")
                                                                         (and v1-compat "HMAC-SHA1"))
                                                   :mac (ensure-vector-length (ensure-vector (secure-random:number #.(expt 2 256)))
                                                                              (string-case (message-field message "openid.session_type")
                                                                                ("DH-SHA1" 20)
                                                                                ("DH-SHA256" 32))))))
                (multiple-value-bind (emac public)
                    (dh-encrypt/decrypt-key
                     (session-digest-type (message-field message "openid.session_type"))
                     (ensure-integer (or (message-field message "openid.dh_gen") +dh-generator+))
                     (ensure-integer (or (message-field message "openid.dh_modulus") +dh-prime+))
                     (ensure-integer (message-field message "openid.dh_consumer_public"))
                     private
                     (association-mac association))
                  (with-lock-held ((associations-lock op))
                    (setf (gethash (association-handle association) (associations op))
                          association))
                  (in-ns (make-message :assoc_handle (association-handle association)
                                       :session_type (message-field message "openid.session_type")
                                       :assoc_type (message-field message "openid.assoc_type")
                                       :expires_in (- (association-expires association)
                                                      (get-universal-time))
                                       :dh_server_public (btwoc public)
                                       :enc_mac_key emac)))))
             (("" "no-encryption")
              (if allow-unencrypted-association-p
                  (let ((association (make-association :association-type (message-field message "openid.assoc_type"))))
                    (with-lock-held ((associations-lock op))
                      (setf (gethash (association-handle association) (associations op))
                            association))
                    (in-ns (make-message :assoc_handle (association-handle association)
                                         :session_type (message-field message "openid.session_type")
                                         :assoc_type (message-field message "openid.assoc_type")
                                         :expires_in (- (association-expires association)
                                                        (get-universal-time))
                                         :mac_key (association-mac association))))
                  (openid-association-error "Unencrypted session is supported only with an encrypted connection.")))
             (t (openid-association-error "Unsupported association type"))))
          200)
          
       (openid-association-error (e)
         (direct-error-response (princ-to-string e)
                                :message (make-message :error_code "unsupported-type"
                                                       :session_type (if v1-compat "DH-SHA1" "DH-SHA256") ; We do not prefer cleartext session, regardless of SSL
                                                       :assoc_type (if v1-compat "HMAC-SHA1" "HMAC-SHA256"))))))

    ("checkid_immediate"
     (with-indirect-error-handler
       (when (message-field message "openid.realm")
         (unless (check-realm (auth-request-realm message)
                              (message-field message "openid.return_to"))
           (signal-indirect-error message "Realm does not match return_to URI.")))
       (indirect-response (message-field message "openid.return_to")
                          (if (handle-checkid-immediate op message)
                              (successful-response-message op message)
                              (setup-needed-response-message op message)))))

    ("checkid_setup"
     (with-indirect-error-handler
       (unless (or (message-field message "openid.realm")
                   (message-field message "openid.return_to"))
         (signal-indirect-error message "At least one of: realm, return_to must be specified."))

       (when (and (message-field message "openid.realm")
                  (message-field message "openid.return_to"))
         (unless (check-realm (message-field message "openid.realm")
                              (message-field message "openid.return_to"))
           (signal-indirect-error message "Realm does not match return_to URI.")))

       (handle-checkid-setup op message)))

    ("check_authentication" ; FIXME: invalidate_handle flow, invalidate unknown/old handles, gc handles, separate place for private handles.
     (values
      (encode-kv (in-ns (make-message
                         :is_valid (if (check-signature (with-lock-held ((associations-lock op))
                                                          (gethash (message-field message "openid.assoc_handle")
                                                                   (associations op)))
                                                        message)
                                       "true"
                                       "false"))))
      200))

    (t (direct-error-response (format nil "Unknown openid.mode ~S"
                                      (message-field message "openid.mode"))))))

