(in-package #:cl-openid)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (unless (boundp '+openid-input-form+)
    (defconstant +openid-input-form+
      "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"
   \"http://www.w3.org/TR/html4/strict.dtd\">
<html><head><title>CL-OpenID login</title></head>
<body><form method=\"GET\"><fieldset>
<legend>OpenID Login</legend>
<input type=\"text\" name=\"openid_identifier\" value=\"\" style=\"background-image: url('http://openid.net/wp-content/uploads/2007/10/openid_small_logo.png');background-position: 0px 0px;background-repeat: no-repeat;padding-left: 20px;\">
<input type=\"submit\" name=\"openid_action\" value=\"Login\"></form></body></html>"
      "Input form for OpenID, for parameterless indirect method endpoint call.")))

(defvar *ids* ()
  "List of handled IDs")

(defvar *ret-params* ()
  "List of received indirect response parameters (for debugging purposes)")

(defun handle-openid-request (uri realm parameters)
  "Handle single OpenID Relying Party request for the received PARAMETERS alist, using URI as return_to address and REALM as a realm.

Returns a string with HTML reply and a redirect URI if applicable."
  (cond ((null parameters)
         +openid-input-form+)

        ((aget "openid_identifier" parameters)
         (let ((id (discover (normalize-identifier (hunchentoot:get-parameter "openid_identifier")))))
           (push id *ids*)
           (values nil (request-authentication-uri id :realm realm :return-to uri))))

        (t (push parameters *ret-params*)
           (format nil
                   "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"
   \"http://www.w3.org/TR/html4/strict.dtd\">
<html><head><title>CL-OpenID result</title></head>
<body>~A
<p>realm: ~A</p>
<dl>~:{<dt>~A</dt><dd>~A</dd>~}</dl>
<a href=\"~A\">return</a>
</body></html>"
                   (let ((reply (handle-indirect-reply parameters (first *ids*) uri)))  ; FIXME: (first *ids*)
                     (case reply
                       (:setup-needed "<h1 style=\"color: orange; text-decoration: blink;\">SETUP NEEDED !!!</h1>")
                       ((nil) "<h1 style=\"color: red; text-decoration: blink;\">ACCESS DENIED !!!</h1>")
                       (t (format nil
                                  "<h1 style=\"color: green; text-decoration: blink;\">ACCESS GRANTED !!!</h1><p>ID: ~A</p>"
                                  reply))))
                   realm
                   (mapcar #'(lambda (c)
                               (list (car c) (cdr c)))
                           parameters)
                   uri))))

;; Hunchentoot-specific part
(defun openid-ht-handler (uri realm)
  "Return a Hunchentoot handler for OpenID request for URI and REALM (closure over HANDLE-OPENID-REQUEST)."
  (let ((u (uri uri))
        (r (uri realm)))
    #'(lambda ()
        (multiple-value-bind (content uri)
            (handle-openid-request u r (hunchentoot:get-parameters))
          (when uri
            (hunchentoot:redirect (princ-to-string uri)))
          content))))

(defun openid-ht-dispatcher (prefix realm &optional (uri (merge-uris prefix (uri realm))))
  "Return a prefix dispatcher for OPENID-HT-HANDLER"
  (hunchentoot:create-prefix-dispatcher prefix (openid-ht-handler uri realm)))

; (hunchentoot:start-server :port 4242)
; (push (openid-ht-dispatcher "/cl-openid" "http://lizard.tasak.gda.pl:4242/") hunchentoot:*dispatch-table*)
