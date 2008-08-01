(in-package #:cl-openid)

(defparameter *assoc-types*
  '(("HMAC-SHA1" . :SHA1)
    ("HMAC-SHA256" . :SHA256)))

(defparameter *session-types*
  '(("DH-SHA1" . :SHA1)
    ("DH-SHA256" . :SHA256)))

(defparameter *https-session-types*
  '("no-encryption" ""))

(defvar *provider-associations* ())

(defun nonce ()
  (multiple-value-bind (sec min hr day mon year wday dst tz)
      (decode-universal-time (get-universal-time) 0)
    (declare (ignore wday dst tz))
    (format nil "~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ~A"
            year mon day hr min sec (gensym)))) ; FIXME:gensym

(defvar *endpoint-uri* nil)

(defun successful-response (parameters)
  (let* ((assoc (or (when (aget "openid.assoc_handle" parameters)
                      (find (aget "openid.assoc_handle" parameters) *provider-associations*
                            :key #'association-handle :test #'string=))
                    (first (push (make-association :hmac-digest :sha256) *provider-associations*))))
         (rv `(("openid.ns" . "http://specs.openid.net/auth/2.0")
               ("openid.mode" . "id_res")
               ("openid.op_endpoint" . ,(princ-to-string *endpoint-uri*))
               ("openid.claimed_id" . ,(aget "openid.identity" parameters))
               ("openid.identity" . ,(aget "openid.identity" parameters))
               ,(assoc "openid.return_to" parameters :test #'string=)
               ("openid.response_nonce" . ,(nonce))
               ("openid.assoc_handle" . ,(string (association-handle assoc)))
               ("openid.signed" . "op_endpoint,identity,claimed_id,return_to,assoc_handle,response_nonce"))))
    (push (cons "openid.sig" (sign assoc rv)) rv)
    rv))

;; FIXME: user_setup_url (14.2.2)
(defun setup-needed-response ()
  '(("openid.ns" . "http://specs.openid.net/auth/2.0")
    ("openid.mode" . "setup_needed")))

(defun cancel-response ()
  '(("openid.ns" . "http://specs.openid.net/auth/2.0")
    ("openid.mode" . "cancel")))

(defvar *checkid-setup-callback* nil)
(defvar *checkid-immediate-callback* nil)

(defun handle-openid-provider-request
    (parameters
     &aux
     (v1-compat (not (string= "http://specs.openid.net/auth/2.0"
                              (aget "openid.ns" parameters)))))
  (string-case (aget "openid.mode" parameters)
    ("associate"
     (encode-kv ; Direct response
      (handler-case
          (string-case (aget "openid.session_type" parameters)
            (("DH-SHA1" "DH-SHA256")
             (let ((private (random +dh-prime+)) ; FIXME:random
                   (association (make-association :association-type (or (aget "openid.assoc_type" parameters)
                                                                        (and v1-compat "HMAC-SHA1")))))
               (multiple-value-bind (emac public)
                   (dh-encrypt/decrypt-key (session-digest-type (aget "openid.session_type" parameters))
                                           (ensure-integer (or (aget "openid.dh_gen" parameters) +dh-generator+))
                                           (ensure-integer (or (aget "openid.dh_modulus" parameters) +dh-prime+))
                                           (ensure-integer (aget "openid.dh_consumer_public" parameters))
                                           private
                                           (association-mac association))
                 (push association *provider-associations*)
                 `(("ns" . "http://specs.openid.net/auth/2.0")
                   ("assoc_handle" . ,(association-handle association))
                   ("session_type" . ,(aget "openid.session_type" parameters))
                   ("assoc_type" . ,(aget "openid.assoc_type" parameters))
                   ("expires_in" . ,(princ-to-string (- (association-expires association)
                                                        (get-universal-time))))
                   ("dh_server_public" . ,(usb8-array-to-base64-string (btwoc public)))
                   ("enc_mac_key" . ,(usb8-array-to-base64-string emac))))))
            (("" "no-encryption")
             (if (hunchentoot:ssl-p)    ; FIXME:hunchentoot
                 (let ((association (make-association :association-type (aget "openid.assoc_type" parameters)))) ; FIXME:random
                   (push association *provider-associations*)
                   `(("ns" . "http://specs.openid.net/auth/2.0")
                     ("assoc_handle" . ,(association-handle association))
                     ("session_type" . ,(aget "openid.session_type" parameters))
                     ("assoc_type" . ,(aget "openid.assoc_type" parameters))
                     ("expires_in" . ,(princ-to-string (- (association-expires association)
                                                          (get-universal-time))))
                     ("mac_key" . ,(usb8-array-to-base64-string (association-mac association)))))
                 (openid-association-error "Unencrypted session is supported only with an encrypted connection.")))
            (t (openid-association-error "Unsupported association type")))

        (openid-association-error (e)
          (error-response (princ-to-string e)
                          :parameters `(("error_code" . "unsupported-type")
                                        ("session_type" . ,(if v1-compat "DH-SHA1" "DH-SHA256")) ; We do not prefer cleartext session, regardless of SSL
                                        ("assoc_type" . ,(if v1-compat "HMAC-SHA1" "HMAC-SHA256"))))))))

    ("checkid_immediate"
     (if *checkid-immediate-callback*
         (funcall *checkid-immediate-callback* parameters)
         (indirect-response (aget "openid.return_to" parameters)
                            (setup-needed-response))))

    ("checkid_setup"
     (if *checkid-setup-callback*
         (funcall *checkid-setup-callback* parameters)
         (indirect-response (aget "openid.return_to" parameters)
                            (cancel-response))))

    ("check_authentication" ; FIXME: invalidate_handle flow, invalidate unknown/old handles, gc handles, separate place for private handles.
     (encode-kv `(("ns" . "http://specs.openid.net/auth/2.0")
                  ("is_valid"
                   . ,(if (check-signature parameters
                                           (find (aget "openid.assoc_handle" parameters)
                                                 *provider-associations*
                                                 :key #'association-handle :test #'string=))
                          "true"
                          "false")))))

    (t (error-response (format nil "Unknown openid.mode ~S" (aget "openid.mode" parameters))))))

;; Hunchentoot-specific part
(defvar *setup-params* (make-hash-table))
(defun handle-checkid-setup (parameters
                             &aux
                             (handle (gentemp "PARM" :cl-openid.ids))
                             (finish-uri (merge-uris "finish-setup" *endpoint-uri*)))
  (setf (gethash handle *setup-params*) parameters)
  (html "Log in?"
        "<h2>Parameters:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<strong><a href=\"~A\">Log in</a> or <a href=\"~A\">cancel</a>?</strong>"
        (mapcar #'(lambda (c)
                    (list (car c) (cdr c)))
                parameters)
        (copy-uri finish-uri :query (format nil "handle=~A&allow=1" handle))
        (copy-uri finish-uri :query (format nil "handle=~A&deny=1" handle))))

(defun finish-checkid-setup (&aux
                             (handle (intern (hunchentoot:get-parameter "handle") :cl-openid.ids))
                             (parameters (gethash handle *setup-params*)))
  (if (hunchentoot:get-parameter "allow")
      (indirect-response (aget "openid.return_to" parameters)
                         (successful-response parameters))
      (indirect-response (aget "openid.return_to" parameters)
                         (cancel-response))))

(defun finish-checkid-handle (endpoint)
  (lambda ()
    (let ((*endpoint-uri* endpoint))
      (finish-checkid-setup))))

(defun provider-ht-handle (endpoint)
  (lambda ()
    (let ((*endpoint-uri* endpoint))
      (handle-openid-provider-request (append (hunchentoot:post-parameters)
                                              (hunchentoot:get-parameters))))))

(defun provider-ht-dispatcher (endpoint prefix)
  (list (hunchentoot:create-prefix-dispatcher (concatenate 'string prefix "finish-setup") (finish-checkid-handle endpoint))
        (hunchentoot:create-prefix-dispatcher prefix (provider-ht-handle (uri endpoint)))))

; (setf hunchentoot:*dispatch-table*
;       (nconc (provider-ht-dispatcher "http://example.com/cl-openid-op/"
;                                      "/cl-openid-op/")
;              hunchentoot:*dispatch-table*)

; (setf *checkid-immediate-callback*
;       #'(lambda (parameters)
;           (indirect-response (aget "openid.return_to" parameters)
;                              (successful-response parameters))))

; FIXME: Hunchentoot headers.lisp:136 (START-OUTPUT): (push 400 hunchentoot:*approved-return-codes*)
