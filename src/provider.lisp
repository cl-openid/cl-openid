(in-package #:cl-openid)

(defvar *provider-associations* ())

(defvar *nonce-counter* 0
  "Counter for nonce generation")

(defun nonce ()
  (multiple-value-bind (sec min hr day mon year wday dst tz)
      (decode-universal-time (get-universal-time) 0)
    (declare (ignore wday dst tz))
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ~A"
            year mon day hr min sec
            (integer-to-base64-string (incf *nonce-counter*)))))

(defvar *endpoint-uri* nil)

(defun successful-response (message)
  (let* ((assoc (or (when (message-field message "openid.assoc_handle")
                      (find (message-field message "openid.assoc_handle")
                            *provider-associations*
                            :key #'association-handle :test #'string=))
                    (first (push (make-association :hmac-digest :sha256) *provider-associations*))))
         (rv (make-message :openid.mode "id_res"
                           :openid.op_endpoint *endpoint-uri*
                           :openid.claimed_id (message-field message "openid.identity")
                           :openid.identity (message-field message "openid.identity")
                           :openid.return_to (message-field message "openid.return_to")
                           :openid.response_nonce (nonce)
                           :openid.assoc_handle (association-handle assoc)
                           :openid.signed "op_endpoint,identity,claimed_id,return_to,assoc_handle,response_nonce")))
    (in-ns (signed assoc rv))))

(define-constant +setup-needed-response+
    (in-ns (make-message :openid.mode "setup_needed")))

;; FIXME: user_setup_url (14.2.2)
(defun setup-needed-response ()
  +setup-needed-response+)

(define-constant +cancel-response+
    (in-ns (make-message :openid.mode "cancel")))

(defun cancel-response ()
  +cancel-response+)

(defvar *checkid-setup-callback* nil)
(defvar *checkid-immediate-callback* nil)

(defun handle-openid-provider-request
    (message
     &aux
     (v1-compat (not (message-v2-p message))))
  (string-case (message-field message "openid.mode")
    ("associate"
     (encode-kv ; Direct response
      (handler-case
          (string-case (message-field message "openid.session_type")
            (("DH-SHA1" "DH-SHA256")
             (let ((private (random +dh-prime+)) ; FIXME:random
                   (association (make-association :association-type (or (message-field message "openid.assoc_type")
                                                                        (and v1-compat "HMAC-SHA1")))))
               (multiple-value-bind (emac public)
                   (dh-encrypt/decrypt-key
                    (session-digest-type (message-field message "openid.session_type"))
                    (ensure-integer (or (message-field message "openid.dh_gen") +dh-generator+))
                    (ensure-integer (or (message-field message "openid.dh_modulus") +dh-prime+))
                    (ensure-integer (message-field message "openid.dh_consumer_public"))
                    private
                    (association-mac association))
                 (push association *provider-associations*)
                 (in-ns (make-message :assoc_handle (association-handle association)
                                      :session_type (message-field message "openid.session_type")
                                      :assoc_type (message-field message "openid.assoc_type")
                                      :expires_in (- (association-expires association)
                                                     (get-universal-time))
                                      :dh_server_public (btwoc public)
                                      :enc_mac_key emac)))))
            (("" "no-encryption")
             (if (hunchentoot:ssl-p)    ; FIXME:hunchentoot
                 (let ((association (make-association :association-type (message-field message "openid.assoc_type")))) ; FIXME:random
                   (push association *provider-associations*)
                   (in-ns (make-message :assoc_handle (association-handle association)
                                        :session_type (message-field message "openid.session_type")
                                        :assoc_type (message-field message "openid.assoc_type")
                                        :expires_in (- (association-expires association)
                                                       (get-universal-time))
                                        :mac_key (association-mac association))))
                 (openid-association-error "Unencrypted session is supported only with an encrypted connection.")))
            (t (openid-association-error "Unsupported association type")))

        (openid-association-error (e)
          (error-response (princ-to-string e)
                          :message (make-message :error_code "unsupported-type"
                                                 :session_type (if v1-compat "DH-SHA1" "DH-SHA256") ; We do not prefer cleartext session, regardless of SSL
                                                 :assoc_type (if v1-compat "HMAC-SHA1" "HMAC-SHA256")))))))

    ("checkid_immediate"
     (indirect-response (message-field message "openid.return_to")
                        (if (and *checkid-immediate-callback*
                                 (funcall *checkid-immediate-callback* message))
                            (successful-response message)
                            (setup-needed-response))))

    ("checkid_setup"
     (if *checkid-setup-callback*
         (funcall *checkid-setup-callback* message)
         (indirect-response (message-field message "openid.return_to")
                            (cancel-response))))

    ("check_authentication" ; FIXME: invalidate_handle flow, invalidate unknown/old handles, gc handles, separate place for private handles.
     (encode-kv (in-ns (make-message
                        :is_valid (if (check-signature message
                                                       (find (message-field message "openid.assoc_handle")
                                                             *provider-associations*
                                                             :key #'association-handle :test #'string=))
                                      "true"
                                      "false")))))

    (t (error-response (format nil "Unknown openid.mode ~S"
                               (message-field message "openid.mode"))))))

(defvar *op-requests* (make-hash-table :test #'equal))
(defvar *op-requests-counter* 0)
(defun new-op-request-handle ()
  (integer-to-base64-string (incf *op-requests-counter*) :uri t))

(defun register-op-request (message &aux (handle (new-op-request-handle)))
  (setf (gethash handle *op-requests*) message)
  handle)
