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
<input type=\"submit\" name=\"openid_action\" value=\"Login\">
<br><label><input type=\"checkbox\" name=\"checkid_immediate\"> Immediate request</label></form>")
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

(defun add-postfix-to-uri (uri postfix
                           &aux (rv (if (uri-p uri)
                                        (copy-uri uri)
                                        (uri uri))))
  "Add POSTFIX (string or symbol) to path part of URI, preserving
query and adding trailing slash to URI if necessary."
  (setf (uri-path rv)
        (concatenate 'string
                     (uri-path rv)
                     (unless (eql #\/ (aref (uri-path rv)
                                            (1- (length (uri-path rv)))))
                       "/")
                     (string postfix)))
  rv)

(defun initiate-authorization (given-id uri realm
                               &key immediate-p
                               &aux
                               (id (discover (normalize-identifier given-id)))
                               (handle (gentemp "ID" (find-package :cl-openid.ids)))
                               (return-to (add-postfix-to-uri uri (symbol-name handle))))
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
          (values nil (initiate-authorization (aget "openid_identifier" parameters) uri realm
                                              :immediate-p (aget "checkid_immediate" parameters)))
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
  "Return a prefix dispatcher for OPENID-HT-HANDLER.

If URI is not supplied, the PREFIX is merged with REALM uri"
  (unless uri
    (setf uri (merge-uris prefix realm)))

  (hunchentoot:create-prefix-dispatcher prefix (openid-ht-handler uri realm prefix)))

; (hunchentoot:start-server :port 4242)
; (push (openid-ht-dispatcher "/cl-openid" "http://lizard.tasak.gda.pl:4242/") hunchentoot:*dispatch-table*)
