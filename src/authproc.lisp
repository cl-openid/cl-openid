;;; -*- lisp -*-
;;; authproc.lisp - a single authentication process conducted by
;;; Relying Party.  Identifier normalization and discovery.

(in-package #:cl-openid)

(defstruct (auth-process
             :conc-name
             (:constructor %make-auth-process))
  "Data structure gathering information about an ongoing authentication process."
  (protocol-version-major 2 :type (unsigned-byte 8))
  (protocol-version-minor 0 :type (unsigned-byte 8))
  (claimed-id nil :type uri)
  (op-local-id nil :type (or uri null))
  (return-to nil :type (or uri null))
  (xrds-location nil :type (or uri null))
  (provider-endpoint-uri nil :type (or uri null))
  (timestamp nil :type (or integer null)))

(defun protocol-version (auth-process)
  "Protocol version of an authentication process, as a cons (MAJOR . MINOR)."
  (cons (protocol-version-major auth-process)
        (protocol-version-minor auth-process)))

(defun (setf protocol-version) (new-value auth-process)
  (setf (protocol-version-major auth-process) (car new-value)
        (protocol-version-minor auth-process) (cdr new-value))
  new-value)

(defun remove-dot-segments (parsed-path)
  "Remove . and .. from parsed URI path, to correctly identify same
  paths and prevent URI traversal attacks."
  (loop
     with traversed = nil  
     for element in (loop
                       for (element next) on (rest parsed-path)
                       for ignored = (member element '("" ".") :test #'string=)
                       when (and next (not ignored)) collect element
                       else when (not next) collect (if ignored
                                                        ""
                                                        element))
     if (and (stringp element)
             (string= element ".."))
     do (pop traversed)
     else do (push element traversed)
     finally (return (cons (first parsed-path)
                           (nreverse traversed)))))

(defun make-auth-process (given-id)
  "Initialize new AUTH-PROCESS structure from a user-given identifier GIVEN-ID (string).

An XRDS location for Yadis discovery discovered by a HEAD request may
be included in returned structure."
  ;; OpenID Authentication 2.0 Final, Section 7.2.  Normalization

  ;; 1., 2.
  (let ((possible-xri (if (string= "xri://" (subseq given-id 0 6))
                          (subseq given-id 6)
                          given-id)))
    (when (member (char possible-xri 0)
                  '(#\= #\@ #\+ #\$ #\! #\())
      ;; input SHOULD be treated as an XRI
      (error "XRI identifiers are not supported.")))

  ;; 3. the input SHOULD be treated as an http URL

  ;; if it does not include a "http" or "https" scheme, the Identifier
  ;; MUST be prefixed with the string "http://"
  (unless (or (string= (subseq given-id 0 5) "http:")
              (string= (subseq given-id 0 6) "https:"))
    (setf given-id (concatenate 'string "http://" given-id)))
  
  (let ((id (uri given-id)))
    ;; If the URL contains a fragment part, it MUST be stripped off
    ;; together with the fragment delimiter character "#"
    (setf (uri-fragment id) nil)

    ;; Host is case-insensitive
    (setf (uri-host id) (string-downcase (uri-host id)))

    ;; Traverse dots and double dots.  What about // in middle of path?
    (setf (uri-parsed-path id)
          (if (uri-parsed-path id)
              (remove-dot-segments (uri-parsed-path id))
              '(:absolute "")))         ; An empty path component is
                                  ; normalized to a slash

    ;; URL Identifiers MUST then be further normalized by both
    ;; following redirects when retrieving their content and finally
    ;; applying the rules in Section 6 of [RFC3986] to the final
    ;; destination URL.
    (multiple-value-bind
          (body-or-stream status-code headers uri stream must-close reason-phrase)
        (http-request id :method :head :close t)
      (declare (ignore body-or-stream stream must-close))
      (unless (= 2 (floor (/ status-code 100))) ; 2xx succesful response
        (error "Could not reach ~A: ~A ~A" id status-code reason-phrase))

      ;; Construct return alist
      (let ((rv (%make-auth-process :claimed-id uri))
            (xrds (assoc :x-xrds-location headers)))
        (when xrds
          (setf (xrds-location rv) (uri (cdr xrds))))
        rv))))

(define-constant +entities+
    '(("amp" . #\&) ("gt" . #\>) ("lt" . #\<) ("quot" . #\"))
  "Alist of HTML entities to be unquoted.")

(defun n-remove-entities (str &optional (entities +entities+))
  "Remove HTML entities from STR, destructively."
  (loop
     for s = (position #\& str) then (position #\& str :start (1+ s))
     for e = (when s
               (position #\; str :start (1+ s)))
     for replacement = (when (and s e)
                         (cdr (assoc (subseq str (1+ s) e) entities
                                     :test #'string-equal)))
     while s
     when replacement
     do (setf (aref str s) replacement
              (subseq str (1+ s)) (subseq str (1+ e))
              str (adjust-array str (- (length str) (- e s))))
     finally (return str)))

(defun perform-html-discovery (authproc body &aux ep oploc ep.1 oploc.1 xrds)
  (macrolet ((setf-to-href (place name rel link)
             "When NAME is in REL list, setf VAR to LINK tag's href."
             `(when (member ,name ,rel :test #'string-equal)
               (setf ,place (getf (cdar ,link) :href)))))
    (flet ((handle-link-tag (link       ; ((:link attrs...))
                             &aux
                             (rel (split-sequence #\Space (getf (cdar link) :rel))))
             (setf-to-href ep "openid2.provider" rel link)
             (setf-to-href oploc "openid2.local_id" rel link)
             (setf-to-href ep.1 "openid.server" rel link)
             (setf-to-href oploc.1 "openid.delegate" rel link))

           (handle-meta-tag (meta)
             (when (string-equal "X-XRDS-Location" (getf (cdar meta) :http-equiv))
               (setf xrds (getf (cdar meta) :content)))))

      (parse-html body :callback-only t
                  :callbacks (acons :link #'handle-link-tag
                                    (acons :meta #'handle-meta-tag
                                           nil)))))
  (cond
    (ep (setf (provider-endpoint-uri authproc) (uri ep)
              (op-local-id authproc) (maybe-uri oploc)
              (protocol-version authproc) '(2 . 0)))
    (ep.1 (setf (provider-endpoint-uri authproc) (uri ep.1)
              (op-local-id authproc) (maybe-uri oploc.1)
              (protocol-version authproc) '(1 . 1))))

  (when xrds
    (setf (xrds-location authproc) (uri xrds)))

  authproc)

(define-constant +protocol-versions+
    '(("http://specs.openid.net/auth/2.0/server" . (2 . 0))
      ("http://specs.openid.net/auth/2.0/signon" . (2 . 0))
      ("http://openid.net/signon/1.0" . (1 . 0))
      ("http://openid.net/server/1.0" . (1 . 0))
      ("http://openid.net/signon/1.1" . (1 . 1))
      ("http://openid.net/server/1.1" . (1 . 1)))
  "OpenID protocol versions for XRDS service type URIs")

(defun perform-xrds-discovery (authproc body
                               &aux (parsed (xmls:parse body))
                               prio endpoint oplocal
                               v1prio v1endpoint v1oplocal v1type)
  (assert (member (car parsed) '(("XRDS" . "xri://$xrds")
                                 ("XRDS" . "xri://\\$xrds")) ; http://www.mediawiki.org/wiki/Extension:OpenID possible bug
                  :test #'equal)
          ((car parsed)))
  (flet ((priority (service)
           "Priority of a service tag: an integer or NIL"
           (let ((prio (second (assoc "priority" (second service)
                                      :test #'string=))))
             (when prio
               (parse-integer prio))))

         (prio< (new old)
           "Test whether NEW priority number is less than OLD.

Takes care for NIL priorities and chooses randomly if both priorities
are the same."
           (if (eql new old)
               (> (random 1.0) 1/2)     ; both NILs or same priority
               (or (null old)           ; NEW is number, OLD is NIL
                   (ignore-errors       ; error if NEW is NIL
                     (< new old)))))

         (uri (service)
           "URI of a service tag as a string"
           (third (find '("URI" . "xri://$xrd*($v*2.0)") service
                        :key #'car :test #'equal))))

    (dolist (service  (remove '("Service" . "xri://$xrd*($v*2.0)")
                              (cddar ; Yadis 1.0, 7.3.1 XRDS -- last XRD element
                               (last (remove '("XRD" . "xri://$xrd*($v*2.0)")
                                             (xmls:node-children parsed)
                                             :test-not #'equal :key #'car)))
                              :test-not #'equal :key #'car))
      (dolist (type (mapcar #'third (remove '("Type" . "xri://$xrd*($v*2.0)")
                                            (xmls:node-children service)
                                            :test-not #'equal :key #'car)))
        (cond
          ;; 2.0
          ((string= type "http://specs.openid.net/auth/2.0/server")
           (let ((sprio (priority service)))
             (when (or (null endpoint) (prio< sprio prio))
               (setf endpoint (uri service)
                     oplocal nil))))

          ((string= type "http://specs.openid.net/auth/2.0/signon")
           (let ((sprio (priority service)))
             (when (or (null endpoint) (prio< sprio prio))
               (setf prio sprio
                     endpoint (uri service)
                     oplocal (third (find '("LocalID" . "xri://$xrd*($v*2.0)")
                                          (xmls:node-children service)
                                          :test #'equal :key #'car))))))

          ;; 1.x
          ((member type '("http://openid.net/server/1.0" "http://openid.net/server/1.1"
                          "http://openid.net/signon/1.0" "http://openid.net/signon/1.1")
                   :test #'string=)
           (let ((sprio (priority service)))
             (when (or (null v1endpoint) (prio< sprio v1prio))
               (setf v1prio sprio
                     v1endpoint (uri service)
                     v1oplocal (let ((delegate (find '("Delegate" . "http://openid.net/xmlns/1.0")
                                                     (xmls:node-children service)
                                                     :test #'equal :key #'car)))
                                 (when delegate
                                   (third delegate)))
                     v1type type))))))))
  (cond
    (endpoint (setf (provider-endpoint-uri authproc) (uri endpoint)
                    (op-local-id authproc) (maybe-uri oplocal)))
    (v1endpoint (setf (protocol-version authproc)  (or (cdr (assoc v1type +protocol-versions+
                                                                   :test #'equal))
                                                       '(1 . 1))
                      (provider-endpoint-uri authproc) (uri v1endpoint)
                      (op-local-id authproc) (maybe-uri v1oplocal))))

  authproc)

(define-condition openid-discovery-error (simple-error)
  ())

(defun openid-discovery-error (format-control &rest format-arguments)
  (error 'openid-discovery-error
         :format-control format-control
         :format-arguments format-arguments))

(defun check-discovery-postcondition (authproc)
  ;; OpenID Authentication 2.0 Final, Section 7.3.1.  Discovered Information

  ;; In fact, the only thing to check is the OP Endpoint URL.
  ;; The spec also states that the protocol version must be known
  ;; after the discovery, but the protocol version has default values
  ;; in the AUTHPROC structure, therefore it's value can't be absent.

  (when (not (provider-endpoint-uri authproc))
    (openid-discovery-error "Failed to perform OpenID discovery. 
The OP Endpoint URL has not been determined by the discovery procedure."))

  authproc)

(defun discover (id
                 &aux
                 (authproc (etypecase id
                             (auth-process id)
                             (string (make-auth-process id))))
                 (request-uri (or (xrds-location authproc)
                                  (claimed-id authproc)))
                 (*text-content-types* (append '(("application" . "xhtml+xml")
                                                 ("application" . "xrds+xml"))
                                               *text-content-types*)))
  "Perform discovery on ID.

ID may be either an already initialized AUTH-PROCESS structure, or
user-given ID string."

  ;; OpenID Authentication 2.0 Final, Section 7.3.  Discovery
  (multiple-value-bind
        (body status-code headers uri stream must-close reason-phrase)
      (http-request request-uri :additional-headers '((:accept-encoding "")))
    (declare (ignore stream must-close))
      
    (unless (= 2 (floor (/ status-code 100))) ; 2xx succesful response
      (error "Could not reach ~A: ~A ~A" request-uri status-code reason-phrase))

    ;; X-XRDS-Location: header check
    (let ((x-xrds-location (maybe-uri (aget :x-xrds-location headers))))
      (when (and x-xrds-location
                 (not (uri= x-xrds-location uri)))
        (setf (xrds-location authproc) x-xrds-location)
        (return-from discover ; Restart discovery process to use Yadis
          (discover authproc))))

    ;; Content-Type: check
    (let ((content-type (multiple-value-list (get-content-type headers))))
      (setf (cddr content-type) nil)    ; drop parameters
      (cond
        ((or (xrds-location authproc)   ; mediawiki OpenID plugin
                                        ; returns XRDS as text/html,
                                        ; so when we ask explicitly
                                        ; for XRDS we assume we
                                        ; received XRDS.
             (equalp '("application" "xrds+xml") content-type))
         (perform-xrds-discovery authproc body))

        ((member content-type '(("text" "html")
                                ("application" "xhtml+xml"))
                 :test #'equalp)
         (perform-html-discovery authproc body)
         (when (xrds-location authproc) ; XRDS location found in HTML
           ;; We go back to perform Yadis discovery.  Maybe we should
           ;; save already discovered info and 
           (return-from discover
             (discover authproc))))

        (t (error "Unsupported content-type ~S at ~A" content-type request-uri)))))

  (check-discovery-postcondition authproc))


;; OpenID Authentication 2.0, 9.  Requesting Authentication
;; http://openid.net/specs/openid-authentication-2_0.html#requesting_authentication
(defun request-authentication-uri (authproc &key realm immediate-p association extra-parameters)
  "URI for an authentication request for AUTHPROC"
  (unless (or (return-to authproc) realm)
    (error "At least one of: (RETURN-TO AUTHPROC), REALM must be specified."))
  (indirect-message-uri (provider-endpoint-uri authproc)
                        (in-ns (apply #'make-message
                                             :openid.mode (if immediate-p
                                                              "checkid_immediate"
                                                              "checkid_setup")
                                             :openid.claimed_id (claimed-id authproc)
                                             :openid.identity (or (op-local-id authproc)
                                                                  (claimed-id authproc))
                                             :openid.assoc_handle (when association
                                                                    (association-handle association))
                                             :openid.return_to (return-to authproc)

                                             (if (= 2 (protocol-version-major authproc))
                                                 :openid.realm ; OpenID 1.x compat: trust_root instead of realm
                                                 :openid.trust_root)
                                             realm
                                             extra-parameters))))

