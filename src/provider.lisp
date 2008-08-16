(in-package #:cl-openid)

;; (use-package :defclass-star)
;; (setf *accessor-name-transformer* #'(lambda (n d) (declare (ignore d)) n))
#+macroexpand-and-paste
(defclass* openid-provider ()
  ((op-endpoint-uri :documentation "OP endpoint URI")
   (associations (make-hash-table :test #'equal)
                 :documentation "OP's associations.")))

(defclass openid-provider ()
  ((op-endpoint-uri :accessor op-endpoint-uri :initarg :op-endpoint-uri
                    :documentation "OP endpoint URI")
   (associations :initform (make-hash-table :test #'equal)
                 :accessor associations :initarg :associations
                 :documentation "OP's associations.")))

(defvar *nonce-counter* 0
  "Counter for nonce generation")

(defun nonce ()
  (multiple-value-bind (sec min hr day mon year wday dst tz)
      (decode-universal-time (get-universal-time) 0)
    (declare (ignore wday dst tz))
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ~A"
            year mon day hr min sec
            (integer-to-base64-string (incf *nonce-counter*)))))

(defconstant +indirect-response-code+ 303)

(defun indirect-response (return-to message)
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
  (encode-kv message))

(define-condition checkid-error (error)
  ((reason :initarg :reason :reader reason)
   (return-to :initform nil :initarg :return-to :reader %return-to))
  (:report (lambda (e s)
             (princ (reason e) s)))
  (:documentation "Error occured during OpenID chekid_setup or checkid_immediate handling.

This condition is handled by HANDLE-OPENID-PROVIDER-REQUEST and, if it
occurs, indirect error response is directed to user."))

(defmacro with-checkid-error-handler (&body body)
  "Handle CHECKID-ERROR in BODY.

When CHECKID-ERROR is signaled, immediately return indirect error response."
  (let ((block-name (gensym "CHECKID-ERROR-HANDLER-BLOCK")))
    `(block ,block-name
       (handler-bind ((checkid-error
                       #'(lambda (e)
                           (return-from ,block-name
                             (if (%return-to e)
                                 (indirect-response (%return-to e)
                                                    (in-ns (make-message :openid.mode "error"
                                                                         :openid.error (princ-to-string e))))
                                 (values (princ-to-string e) 400))))))
         ,@body))))

;;; Positive assertion generation
(defun successful-response-message (op message)
  (let* ((assoc (or (gethash (message-field message "openid.assoc_handle")
                             (associations op))
                    (let ((new-association (make-association
                                            :hmac-digest (if (message-v2-p message)
                                                             :sha256
                                                             :sha1))))
                      (setf (gethash (association-handle new-association) (associations op))
                            new-association)
                      new-association)))
         (rv (make-message :openid.mode "id_res"
                           :openid.op_endpoint (op-endpoint-uri op)
                           :openid.claimed_id (message-field message "openid.identity")
                           :openid.identity (message-field message "openid.identity")
                           :openid.return_to (message-field message "openid.return_to")
                           :openid.response_nonce (nonce)
                           :openid.assoc_handle (association-handle assoc)
                           :openid.signed "op_endpoint,identity,claimed_id,return_to,assoc_handle,response_nonce"
                           ;; FIXME:invalidate_handle
                           )))
    (in-ns (signed assoc rv))))

(defun successful-response (op message)
  (indirect-response (message-field message "openid.return_to")
                     (successful-response-message op message)))

;;; Setup needed message generation
(defgeneric user-setup-url (op message)
  (:documentation "Return URI for user setup to return on failed immediate request.")
  (:method (op message)
    (declare (ignore op message))
    nil))

(define-constant +setup-needed-response-message+
    (in-ns (make-message :openid.mode "setup_needed")))

(defun setup-needed-response-message (op message)
  (copy-message +setup-needed-response-message+
                :openid.user_setup_url (user-setup-url op message)))

(defun setup-needed-response (op message)
  (indirect-response (message-field message "openid.return_to")
                     (setup-needed-response-message op message)))

;;; Negative assertion generation
(define-constant +cancel-response-message+
    (in-ns (make-message :openid.mode "cancel")))

(defun cancel-response (op message)
  (declare (ignore op))
  (indirect-response (message-field message "openid.return_to")
                     +cancel-response-message+))


(defgeneric handle-checkid-setup (op message)
  (:documentation "Handle checkid_setup requests.")
  (:method (op message)
    (if (message-field message "openid.return_to")
        (cancel-response op message)
        (values "CANCEL" 400))))

(defgeneric handle-checkid-immediate (op message)
  (:documentation "Handle checkid_immediate requests.")
  (:method (op message)
    "Always fail"
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

(defun handle-openid-provider-request (op message &key secure-p
                                       &aux (v1-compat (not (message-v2-p message))))
  (string-case (message-field message "openid.mode")
    ("associate"
     (encode-kv ; Direct response
      (handler-case
          (string-case (message-field message "openid.session_type")
            (("DH-SHA1" "DH-SHA256")
             (let ((private (random +dh-prime+)) ; FIXME:random
                   (association (make-association :association-type (or (message-field message "openid.assoc_type")
                                                                        (and v1-compat "HMAC-SHA1"))
                                                  :mac (ensure-vector-length (ensure-vector (random #.(expt 2 256))) ; FIXME:random
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
                 (setf (gethash (association-handle association) (associations op))
                       association)
                 (in-ns (make-message :assoc_handle (association-handle association)
                                      :session_type (message-field message "openid.session_type")
                                      :assoc_type (message-field message "openid.assoc_type")
                                      :expires_in (- (association-expires association)
                                                     (get-universal-time))
                                      :dh_server_public (btwoc public)
                                      :enc_mac_key emac)))))
            (("" "no-encryption")
             (if secure-p
                 (let ((association (make-association :association-type (message-field message "openid.assoc_type"))))
                   (setf (gethash (association-handle association) (associations op))
                         association)
                   (in-ns (make-message :assoc_handle (association-handle association)
                                        :session_type (message-field message "openid.session_type")
                                        :assoc_type (message-field message "openid.assoc_type")
                                        :expires_in (- (association-expires association)
                                                       (get-universal-time))
                                        :mac_key (association-mac association))))
                 (openid-association-error "Unencrypted session is supported only with an encrypted connection.")))
            (t (openid-association-error "Unsupported association type")))

        (openid-association-error (e)
          (direct-error-response (princ-to-string e)
                                 :message (make-message :error_code "unsupported-type"
                                                        :session_type (if v1-compat "DH-SHA1" "DH-SHA256") ; We do not prefer cleartext session, regardless of SSL
                                                        :assoc_type (if v1-compat "HMAC-SHA1" "HMAC-SHA256")))))))

    ("checkid_immediate"
     (with-checkid-error-handler
       (when (message-field message "openid.realm")
         (unless (check-realm (message-field message "openid.realm")
                              (message-field message "openid.return_to"))
           (error 'checkid-error :reason "Realm does not match return_to URI.")))
       (indirect-response (message-field message "openid.return_to")
                          (if (handle-checkid-immediate op message)
                              (successful-response-message op message)
                              (setup-needed-response-message op message)))))

    ("checkid_setup"
     (with-checkid-error-handler
       (unless (or (message-field message "openid.realm")
                   (message-field message "openid.return_to"))
         (error 'checkid-error
                :reason "At least one of: realm, return_to must be specified."
                :return-to (message-field message "openid.return_to")))

       (when (and (message-field message "openid.realm")
                  (message-field message "openid.return_to"))
         (unless (check-realm (message-field message "openid.realm")
                              (message-field message "openid.return_to"))
           (error 'checkid-error
                  :reason "Realm does not match return_to URI."
                  :return-to (message-field message "openid.return_to"))))

       (handle-checkid-setup op message)))

    ("check_authentication" ; FIXME: invalidate_handle flow, invalidate unknown/old handles, gc handles, separate place for private handles.
     (encode-kv (in-ns (make-message
                        :is_valid (if (check-signature (gethash (message-field message "openid.assoc_handle")
                                                                (associations op))
                                                       message)
                                      "true"
                                      "false")))))

    (t (direct-error-response (format nil "Unknown openid.mode ~S"
                                      (message-field message "openid.mode"))))))

