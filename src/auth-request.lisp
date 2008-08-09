(in-package #:cl-openid)

;; OpenID Authentication 2.0, 9.  Requesting Authentication
;; http://openid.net/specs/openid-authentication-2_0.html#requesting_authentication
(defun request-authentication-uri (authproc &key return-to realm immediate-p
                                   &aux (association (associate authproc)))
  "Return URI for an authentication request for ID"
  (unless (or return-to realm)
    (error "Either RETURN-TO, or REALM must be specified."))
  (indirect-request-uri (endpoint-uri authproc)
                        (make-message :openid.mode (if immediate-p
                                                       "checkid_immediate"
                                                       "checkid_setup")
                                      :openid.claimed_id (claimed-id authproc)
                                      :openid.identity (or (op-local-id authproc)
                                                           (claimed-id authproc))
                                      :openid.assoc_handle (when association
                                                             (association-handle association))
                                      :openid.return_to return-to

                                      (if (= 2 (protocol-version-major authproc))
                                          :openid.realm  ; OpenID 1.x compat: trust_root instead of realm
                                          :openid.trust_root)
                                      realm)))

(define-condition openid-assertion-error (error)
  ((code :initarg :code :reader code)
   (reason :initarg :reason :reader reason)
   (reason-format-parameters :initarg :reason-format-parameters :reader reason-format-parameters)
   (authproc :initarg :authproc :reader authproc)
   (message :initarg :message :reader message))
  (:report (lambda (e s)
             (format s "OpenID assertion error: ~?"
                     (reason e) (reason-format-parameters e))))
  (:documentation "Error during OpenID assertion verification"))

(defvar *nonces* nil
  "A list of openid.nonce response parameters to avoid duplicates.")

(defvar *nonce-timeout* 3600
  "Number of seconds the nonce times out.")

(defun nonce-universal-time (nonce)
  (encode-universal-time (parse-integer nonce :start 17 :end 19) ; second
                         (parse-integer nonce :start 14 :end 16) ; minute
                         (parse-integer nonce :start 11 :end 13) ; hour
                         (parse-integer nonce :start 8  :end 10) ; date
                         (parse-integer nonce :start 5  :end 7)  ; month
                         (parse-integer nonce :start 0  :end 4)  ; year
                         0                                       ; GMT
                         ))

(defun gc-nonces (&aux (time-limit (- (get-universal-time) *nonce-timeout*)))
  (setf *nonces* (delete-if #'(lambda (nonce-time)
                                (< nonce-time time-limit))
                            *nonces* :key #'nonce-universal-time)))

(defun handle-indirect-response (message authproc
                                 &aux (v1-compat (not (= 2 (protocol-version-major authproc)))))
  "Handle indirect response MESSAGE directed for AUTHPROC.

Returns AUTHPROC on success, NIL on failure."
  (macrolet ((err (code reason &rest args) ; FIXME:macrolet (use FLET)
               `(error 'openid-assertion-error
                       :code ,code
                       :reason ,reason
                       :reason-format-parameters (list ,@args)
                       :message message
                       :authproc authproc))
             (ensure (test-form code message &rest args)
               `(unless ,test-form
                  (err ,code ,message ,@args)))
             (same-uri (ap-accessor field-name)
               `(uri= (uri (,ap-accessor authproc))
                      (uri (message-field message ,field-name)))))

    (string-case (message-field message "openid.mode")
      ("error" (err :server-error "Assertion error"))

      ("setup_needed" (err :setup-needed "Setup needed."))

      ("cancel" nil)

      ("id_res"

       ;; Handle assoc invalidations
       (gc-associations (message-field message "openid.invalidate_handle"))

       ;; 11.1.  Verifying the Return URL
       (ensure (uri= (return-to authproc)
                     (uri (message-field message "openid.return_to")))
               :invalid-return-to
               "openid.return_to ~A doesn't match server's URI" (message-field message "openid.return_to"))

       ;; 11.2.  Verifying Discovered Information
       (unless v1-compat
         (ensure (string= +openid2-namespace+ (message-field message "openid.ns"))
                 :invalid-namespace
                 "Wrong namespace ~A" (message-field message "openid.ns")))

       (unless (and v1-compat (null (message-field message "openid.op_endpoint")))
         (ensure (same-uri endpoint-uri "openid.op_endpoint")
                 :invalid-endpoint
                 "Endpoint URL does not match previously discovered information."))

       (unless (or (and v1-compat
                        (null (message-field message "openid.claimed_id")))
                   (same-uri claimed-id "openid.claimed_id"))
         (let ((cap (discover (message-field message "openid.claimed_id"))))
           (if (uri= (endpoint-uri cap) (endpoint-uri authproc))
               (setf (claimed-id authproc) (claimed-id cap))
               (err :invalid-claimed-id
                    "Received Claimed ID ~A differs from user-supplied ~A, and discovery for received one did not find the same endpoint."
                    (endpoint-uri authproc) (endpoint-uri cap)))))

       ;; 11.3.  Checking the Nonce
       (let ((nonce (message-field message "openid.response_nonce")))
         (if nonce
             (progn (ensure (not (or (> (- (get-universal-time)
                                           (nonce-universal-time nonce))
                                        *nonce-timeout*)
                                     (member nonce *nonces* :test #'string=)))
                            :invalid-nonce
                            "Repeated nonce.")
                    (push nonce *nonces*))
             (unless v1-compat
               (err :missing-nonce "No openid.response_noce"))))
       (gc-nonces)

       ;; 11.4.  Verifying Signatures
       (ensure (if (association-by-handle (message-field message "openid.assoc_handle"))
                   ;; 11.4.1.  Verifying with an Association
                   (check-signature message)
                   ;; 11.4.2.  Verifying Directly with the OpenID Provider
                   (let ((response (direct-request (endpoint-uri authproc)
                                                (acons "openid.mode" "check_authentication"
                                                       (remove "openid.mode" message
                                                               :key #'car
                                                               :test #'string=)))))

                     (when (message-field response "invalidate_handle")
                       (gc-associations (message-field response "invalidate_handle")))
                     (string= "true" (message-field response "is_valid"))))
               :invalid-signature
               "Invalid signature")

       (unless v1-compat             ; Check list of signed parameters
         (let ((signed (split-sequence #\, (message-field message "openid.signed"))))
           (ensure (every #'(lambda (f)
                              (member f signed :test #'string=))
                          `("op_endpoint"
                            "return_to"
                            "response_nonce"
                            "assoc_handle"
                            ,@(when (message-field message "openid.claimed_id")
                                    '("claimed_id" "identity"))))
                   :invalid-signed-fields
                   "Not all fields that are required to be signed, are so.")))

       authproc))))
