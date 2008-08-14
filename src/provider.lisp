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
  (values (indirect-response-uri return-to message)
          +indirect-response-code+))

(defun error-response (err &key contact reference message)
  (values (encode-kv (error-response-message err
                                             :contact contact
                                             :reference reference
                                             :message message))
          400))

(defun direct-response (message)
  (encode-kv message))

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
    (cancel-response op message)))

(defgeneric handle-checkid-immediate (op message)
  (:documentation "Handle checkid_immediate requests.")
  (:method (op message)
    "Always fail"
    (declare (ignore op message))
    nil))


(defgeneric allow-unencrypted-association-p (op message)
  (:documentation "Decide whether to allow unencrypted associations.

By default, always disallow.")
  (:method (op message)
    (declare (ignore op message))
    nil))


(defun handle-openid-provider-request (op message &aux (v1-compat (not (message-v2-p message))))
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
             (if (allow-unencrypted-association-p op message)
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
          (error-response (princ-to-string e)
                          :message (make-message :error_code "unsupported-type"
                                                 :session_type (if v1-compat "DH-SHA1" "DH-SHA256") ; We do not prefer cleartext session, regardless of SSL
                                                 :assoc_type (if v1-compat "HMAC-SHA1" "HMAC-SHA256")))))))

    ("checkid_immediate"
     (indirect-response (message-field message "openid.return_to")
                        (if (handle-checkid-immediate op message)
                            (successful-response-message op message)
                            (setup-needed-response-message op message))))

    ("checkid_setup" (handle-checkid-setup op message))

    ("check_authentication" ; FIXME: invalidate_handle flow, invalidate unknown/old handles, gc handles, separate place for private handles.
     (encode-kv (in-ns (make-message
                        :is_valid (if (check-signature (gethash (message-field message "openid.assoc_handle")
                                                                (associations op))
                                                       message)
                                      "true"
                                      "false")))))

    (t (error-response (format nil "Unknown openid.mode ~S"
                               (message-field message "openid.mode"))))))

