(in-package #:cl-openid)

;; (use-package :defclass-star)
;; (setf *accessor-name-transformer* #'(lambda (n d) (declare (ignore d)) n))
#+macroexpand-and-paste
(defclass* relying-party ()
  ((root-uri :documentation "RP's root URI")
   (realm :documentation "Realm URI")
   (associations (make-hash-table :test #'equalp)
                 :documentation "Associated endpoints, indexed by endpoint URIs")
   (authprocs (make-hash-table :test #'equal)
              :documentation "Handled authenticaction processes")
   (authproc-timeout 3600 :documentation "Number of seconds after which an AUTH-PROCESS is collected from AUTHPROCS slot")
   (nonces () :documentation "A list of openid.nonce response parameters to avoid duplicates.")
   (nonce-timeout 3600 :documentation "Number of seconds the nonce times out."))
  (:documentation "The Relying Party server class."))

(defclass relying-party ()
  ((root-uri :accessor root-uri :initarg :root-uri
             :documentation "RP's root URI")
   (realm :accessor realm :initarg :realm
          :documentation "Realm URI")
   (associations :initform (make-hash-table :test #'equalp)
                 :accessor associations :initarg :associations
                 :documentation "Associated endpoints, indexed by endpoint URIs")
   (authprocs :initform (make-hash-table :test #'equal)
              :accessor authprocs :initarg :authprocs
              :documentation "Handled authenticaction processes")
   (authproc-timeout :initform 3600 :accessor authproc-timeout :initarg :authproc-timeout
                     :documentation "Number of seconds after which an AUTH-PROCESS is collected from AUTHPROCS slot")
   (nonces :initform () :accessor nonces :initarg :nonces
           :documentation "A list of openid.nonce response parameters to avoid duplicates.")
   (nonce-timeout :initform 3600 :accessor nonce-timeout :initarg :nonce-timeout
                  :documentation "Number of seconds the nonce times out."))
  (:documentation "The Relying Party server class."))

;; RP associations
(defun gc-associations (rp &optional invalidate-handle &aux (time (get-universal-time)))
  (maphash #'(lambda (ep association)
               (when (or (> time (association-expires association))
                         (and invalidate-handle
                              (string= invalidate-handle (association-handle association))))
                 (remhash ep (associations rp))))
           (associations rp)))

(defun association (rp endpoint &optional v1)
  (gc-associations rp)                  ; keep clean
  (setf endpoint (uri endpoint))        ; make sure it's an URI object
  (or (gethash endpoint (associations rp))
      (setf (gethash endpoint (associations rp))
            (associate endpoint :v1 v1))))

(defun ap-association (rp authproc)
  (association rp (endpoint-uri authproc)
               (= 1 (protocol-version-major authproc))))

(defun association-by-handle (rp handle)
  (maphash #'(lambda (ep assoc)
               (declare (ignore ep))
               (when (string= handle (association-handle assoc))
                 (return-from association-by-handle assoc)))
           (associations rp)))

;; Auth processes
(defun gc-authprocs (rp &aux (time-limit (- (get-universal-time) (authproc-timeout rp))))
  "Collect old auth-process objects from relying party RP."
  (maphash #'(lambda (k v)
               (when (< (timestamp v) time-limit)
                 (remhash k (authprocs rp))))
           (authprocs rp)))

(defun authproc-by-handle (rp handle)
  (or (gethash handle (authprocs rp))
      (error "Don't know authentication-process with handle ~A" handle)))

(defvar *auth-handle-counter* 0 ; This will stay global, and I think it should be less predictable.
  "Counter for unique association handle generation")

(defun new-authproc-handle ()
  "Return new unique authentication handle as string"
  (integer-to-base64-string (incf *auth-handle-counter*) :uri t))

(define-constant +authproc-handle-parameter+ "cl-openid.authproc-handle")

(defun initiate-authentication (rp given-id
                               &key immediate-p
                               &aux
                               (authproc (discover given-id))
                               (handle (new-authproc-handle)))
  "Initiate authentication process.  Returns URI to redirect user to."
  (gc-authprocs rp)
  (setf (timestamp authproc) (get-universal-time)
        (gethash handle (authprocs rp)) authproc

        (return-to authproc)
        (copy-uri (root-uri rp)
                  :query (drakma::alist-to-url-encoded-string
                          (acons +authproc-handle-parameter+ handle nil)
                          :utf-8)))
  (request-authentication-uri authproc
                              :immediate-p immediate-p
                              :realm (realm rp)
                              :association (ap-association rp authproc)))

;; Nonces
(defun nonce-universal-time (nonce)
  (encode-universal-time (parse-integer nonce :start 17 :end 19) ; second
                         (parse-integer nonce :start 14 :end 16) ; minute
                         (parse-integer nonce :start 11 :end 13) ; hour
                         (parse-integer nonce :start 8  :end 10) ; date
                         (parse-integer nonce :start 5  :end 7)  ; month
                         (parse-integer nonce :start 0  :end 4)  ; year
                         0                                       ; GMT
                         ))

(defun gc-nonces (rp &aux (time-limit (- (get-universal-time) (nonce-timeout rp))))
  (setf (nonces rp)
        (delete-if #'(lambda (nonce-time)
                       (< nonce-time time-limit))
                   (nonces rp)
                   :key #'nonce-universal-time)))

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

(defun handle-indirect-response (rp message &optional authproc)
  "Handle indirect response MESSAGE directed for AUTHPROC.

If AUTHPROC is not supplied, its handle is taken from MESSAGE.
Returns AUTHPROC on success, NIL on failure."
  (setf authproc
        (etypecase authproc
          (auth-process authproc)
          (string (authproc-by-handle rp authproc))
          (null (authproc-by-handle rp (message-field message +authproc-handle-parameter+)))))
  
  (let ((v1-compat (not (= 2 (protocol-version-major authproc)))))
    (labels ((err (code reason &rest args)
               (error 'openid-assertion-error
                      :code code
                      :reason reason
                      :reason-format-parameters args
                      :message message
                      :authproc authproc))
             (ensure (test code message &rest args)
               (unless test
                 (apply #'err code message args)))
             (same-uri (ap-accessor field-name)
               (uri= (uri (funcall ap-accessor authproc))
                     (uri (message-field message field-name)))))

      (string-case (message-field message "openid.mode")
        ("error" (err :server-error "Assertion error"))

        ("setup_needed" (err :setup-needed "Setup needed."))

        ("cancel" nil)

        ("id_res"

         ;; Handle assoc invalidations
         (gc-associations rp (message-field message "openid.invalidate_handle"))

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
           (ensure (same-uri #'endpoint-uri "openid.op_endpoint")
                   :invalid-endpoint
                   "Endpoint URL does not match previously discovered information."))

         (unless (or (and v1-compat
                          (null (message-field message "openid.claimed_id")))
                     (same-uri #'claimed-id "openid.claimed_id"))
           (let ((cap (discover (message-field message "openid.claimed_id"))))
             (if (uri= (endpoint-uri cap) (endpoint-uri authproc))
                 (setf (claimed-id authproc) (claimed-id cap)) ; Accept claimed ID change
                 (err :invalid-claimed-id
                      "Received Claimed ID ~A differs from user-supplied ~A, and discovery for received one did not find the same endpoint."
                      (endpoint-uri authproc) (endpoint-uri cap)))))

         ;; 11.3.  Checking the Nonce
         (let ((nonce (message-field message "openid.response_nonce")))
           (if nonce
               (progn (ensure (not (or (> (- (get-universal-time)
                                             (nonce-universal-time nonce))
                                          (nonce-timeout rp))
                                       (member nonce (nonces rp) :test #'string=)))
                              :invalid-nonce
                              "Repeated nonce.")
                      (push nonce (nonces rp)))
               (unless v1-compat
                 (err :missing-nonce "No openid.response_noce"))))
         (gc-nonces rp)

         ;; 11.4.  Verifying Signatures
         (let ((association (association-by-handle rp (message-field message "openid.assoc_handle"))))
           (ensure (if association
                       ;; 11.4.1.  Verifying with an Association
                       (check-signature association message)
                       ;; 11.4.2.  Verifying Directly with the OpenID Provider
                       (let ((response (direct-request (endpoint-uri authproc)
                                                       (acons "openid.mode" "check_authentication"
                                                              (remove "openid.mode" message
                                                                      :key #'car
                                                                      :test #'string=)))))

                         (when (message-field response "invalidate_handle")
                           (gc-associations (message-field response "invalidate_handle")))
                         (string= "true" (message-field response "is_valid"))))
                   :invalid-signature "Invalid signature"))

         (unless v1-compat           ; Check list of signed parameters
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

         authproc)))))
