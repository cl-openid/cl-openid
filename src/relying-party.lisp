(in-package #:cl-openid)

(define-constant +openid-input-form+
    (html "CL-OpenID login"
          "<form method=\"GET\"><fieldset><legend>OpenID Login</legend>
<input type=\"text\" name=\"openid_identifier\" value=\"\" style=\"background-image: url('http://openid.net/wp-content/uploads/2007/10/openid_small_logo.png');background-position: 0px 0px;background-repeat: no-repeat;padding-left: 20px;\">
<input type=\"submit\" name=\"openid_action\" value=\"Login\">
<br><label><input type=\"checkbox\" name=\"checkid_immediate\"> Immediate request</label></form>")
  "Input form for OpenID, for parameterless indirect method endpoint call.")

(defvar *ids* (make-hash-table :test #'equal)
  "List of handled IDs")

(defvar *id-timeout* 3600
  "Number of seconds after which an ID is collected from *IDS*")

(defun gc-ids (&aux (time-limit (- (get-universal-time) *id-timeout*)))
  "Collect old IDs."
  (maphash #'(lambda (k v)
               (when (< (aget :timestamp v) time-limit)
                 (remhash k *ids*)))
           *ids*))

(defvar *auth-handle-counter* 0
  "Counter for unique association handle generation")

(defun new-auth-handle ()
  "Return new unique authentication handle as string"
  (integer-to-base64-string (incf *auth-handle-counter*) :uri t))

(defun initiate-authentication (given-id uri realm
                               &key immediate-p
                               &aux
                               (id (discover (normalize-identifier given-id)))
                               (handle (new-auth-handle))
                               (return-to (add-postfix-to-uri uri handle)))
  "Initiate authentication process.  Returns URI to redirect user to."
  (gc-ids)
  (push (cons :timestamp (get-universal-time)) id)
  (push (cons :return-to return-to) id)
  (setf (gethash handle *ids*) id)
  (request-authentication-uri id
                              :immediate-p immediate-p
                              :realm realm
                              :return-to return-to))

(defun handle-openid-request (uri realm message postfix)
  "Handle single OpenID Relying Party request for the received MESSAGE, using URI as return_to address and REALM as a realm.

Returns a string with HTML response and a redirect URI if applicable."
  (if (null postfix)
      (if (aget "openid_identifier" message)
          (values nil (initiate-authentication (aget "openid_identifier" message) uri realm
                                              :immediate-p (aget "checkid_immediate" message)))
          +openid-input-form+)
      (handler-case
          (html "CL-OpenID result"
                "~A <p><strong>realm:</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>"
                (let ((id (handle-indirect-response message (gethash postfix *ids*))))
                  (if id
                      (format nil
                              "<h1 style=\"color: green; text-decoration: blink;\">ACCESS GRANTED !!!</h1><p>ID: <code>~A</code></p>"
                              (hunchentoot:escape-for-html (prin1-to-string id))) ; FIXME:hunchentoot
                      "<h1 style=\"color: red; text-decoration: blink;\">ACCESS DENIED !!!</h1>"))
                realm
                (mapcar #'(lambda (c)
                            (list (car c) (cdr c)))
                        message)
                uri)
        (openid-assertion-error (e)
          (html "CL-OpenID assertion error"
                "<h1 style=\"color: red; text-decoration: blink;\">ERROR ERROR ERROR !!!</h1>
<p><strong>~S</strong> ~A</p>
<h2>Response:</h2>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<p style=\"text-align:right;\"><a href=\"~A\">return</a><p>
"
                (code e) e
                (mapcar #'(lambda (c)
                            (list (car c) (cdr c)))
                        (message e))
                uri)))))

;; Hunchentoot-specific part
(defun openid-ht-handler (uri realm prefix)
  "Return a Hunchentoot handler for OpenID request for URI and REALM (closure over HANDLE-OPENID-REQUEST)."
  (let ((u (uri uri))
        (r (uri realm))
        (l (1+ (length prefix))))
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
