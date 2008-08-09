(in-package #:cl-openid)

(defvar *authprocs* (make-hash-table :test #'equal)
  "Handled authenticaction processes")

(defvar *authproc-timeout* 3600
  "Number of seconds after which an AUTH-PROCESS is collected from *AUTHPROCS*")

(defun gc-authprocs (&aux (time-limit (- (get-universal-time) *authproc-timeout*)))
  "Collect old IDs."
  (maphash #'(lambda (k v)
               (when (< (timestamp v) time-limit)
                 (remhash k *authprocs*)))
           *authprocs*))

(defvar *auth-handle-counter* 0
  "Counter for unique association handle generation")

(defun new-auth-handle ()
  "Return new unique authentication handle as string"
  (integer-to-base64-string (incf *auth-handle-counter*) :uri t))

(defun initiate-authentication (given-id uri realm
                               &key immediate-p
                               &aux
                               (authproc (discover given-id))
                               (handle (new-auth-handle))
                               (return-to (add-postfix-to-uri uri handle)))
  "Initiate authentication process.  Returns URI to redirect user to."
  (gc-authprocs)
  (setf (timestamp authproc) (get-universal-time)
        (return-to authproc) return-to)
  (setf (gethash handle *authprocs*) authproc)
  (request-authentication-uri authproc
                              :immediate-p immediate-p
                              :realm realm
                              :return-to return-to))

