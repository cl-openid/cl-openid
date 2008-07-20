(in-package #:cl-openid)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defun html (title body &rest body-args)
    "Format HTML."
    (format nil "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"
   \"http://www.w3.org/TR/html4/strict.dtd\">
<html><head><title>~A</title></head>
<body>~?</body></html>"
            title body body-args)))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (boundp '+openid-input-form+)
    (defconstant +openid-input-form+
      (html "CL-OpenID login"
            "<form method=\"GET\"><fieldset><legend>OpenID Login</legend>
<input type=\"text\" name=\"openid_identifier\" value=\"\" style=\"background-image: url('http://openid.net/wp-content/uploads/2007/10/openid_small_logo.png');background-position: 0px 0px;background-repeat: no-repeat;padding-left: 20px;\">
<input type=\"submit\" name=\"openid_action\" value=\"Login\"></form>")
      "Input form for OpenID, for parameterless indirect method endpoint call.")))

(defvar *ids* (make-hash-table)
  "List of handled IDs")

(defvar *id-timeout* 3600
  "Number of seconds after which an ID is collected from *IDS*")

(defun gc-ids (&aux (time-limit (- (get-universal-time) *id-timeout*)))
  "Collect old IDs."
  (maphash #'(lambda (k v)
               (when (< (aget :timestamp v) time-limit)
                 (remhash k *ids*)))
           *ids*))

(defpackage :cl-openid.ids
  (:use)
  (:documentation "Package for unique keys to *IDS* hashtable."))

(defun initiate-authorization (given-id uri realm
                               &key immediate-p
                               &aux
                               (id (discover (normalize-identifier given-id)))
                               (handle (gentemp "ID" (find-package :cl-openid.ids)))
                               (return-to (merge-uris (symbol-name handle) uri)))
  "Initiate authorization process.  Returns URI to redirect user to."
  (gc-ids)
  (push (cons :timestamp (get-universal-time)) id)
  (push (cons :return-to return-to) id)
  (setf (gethash handle *ids*) id)
  (request-authentication-uri id
                              :immediate-p immediate-p
                              :realm realm
                              :return-to return-to))

(defun handle-openid-request (uri realm parameters postfix)
  "Handle single OpenID Relying Party request for the received PARAMETERS alist, using URI as return_to address and REALM as a realm.

Returns a string with HTML reply and a redirect URI if applicable."
  (if (null postfix)
      (if (aget "openid_identifier" parameters)
          (values nil (initiate-authorization (aget "openid_identifier" parameters) uri realm))
          +openid-input-form+)
      (handler-case
          (html "CL-OpenID result"
                "~A <p><strong>realm:</strong> ~A</p>
<h2>Reply parameters:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
                (let ((id (handle-indirect-reply parameters (gethash (intern postfix :cl-openid.ids) *ids*))))
                  (if id
                      (format nil
                              "<h1 style=\"color: green; text-decoration: blink;\">ACCESS GRANTED !!!</h1><p>ID: <code>~A</code></p>"
                              (hunchentoot:escape-for-html (prin1-to-string id))) ; FIXME:hunchentoot
                      "<h1 style=\"color: red; text-decoration: blink;\">ACCESS DENIED !!!</h1>"))
                realm
                (mapcar #'(lambda (c)
                            (list (car c) (cdr c)))
                        parameters)
                uri)
        (openid-assertion-error (e)
          (html "CL-OpenID assertion error"
                "<h1 style=\"color: red; text-decoration: blink;\">ERROR ERROR ERROR !!!</h1>
<p><strong>~S</strong> ~A</p>
<h2>Reply parameters:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>
"
                (code e) e
                (mapcar #'(lambda (c)
                            (list (car c) (cdr c)))
                        (assertion e))
                uri)))))

;; Hunchentoot-specific part
(defun openid-ht-handler (uri realm prefix)
  "Return a Hunchentoot handler for OpenID request for URI and REALM (closure over HANDLE-OPENID-REQUEST)."
  (let ((u (uri uri))
        (r (uri realm))
        (l (length prefix)))
    #'(lambda ()
        (multiple-value-bind (content uri)
            (handle-openid-request u r (hunchentoot:get-parameters)
                                   ;; Postfix
                                   (when (> (length (hunchentoot:script-name)) l)
                                     (subseq (hunchentoot:script-name) l)))
          (when uri
            (hunchentoot:redirect (princ-to-string uri)))
          content))))

(defun openid-ht-dispatcher (prefix realm &optional uri)
  "Return a prefix dispatcher for OPENID-HT-HANDLER."
  ;; Ensure trailing slash.
  (unless (eql #\/ (aref prefix (1- (length prefix))))
    (setf prefix (concatenate 'string prefix "/")))

  (unless uri
    (setf uri (merge-uris prefix (uri realm))))

  (hunchentoot:create-prefix-dispatcher prefix (openid-ht-handler uri realm prefix)))

; (hunchentoot:start-server :port 4242)
; (push (openid-ht-dispatcher "/cl-openid" "http://lizard.tasak.gda.pl:4242/") hunchentoot:*dispatch-table*)
