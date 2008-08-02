;;; -*- lisp -*-
;;; identifier.lisp - OpenID Identifier API

(in-package #:cl-openid)

(define-constant +protocol-versions+
    '(("http://specs.openid.net/auth/2.0/server" . (2 . 0))
      ("http://specs.openid.net/auth/2.0/signon" . (2 . 0))
      ("http://openid.net/signon/1.0" . (1 . 0))
      ("http://openid.net/server/1.0" . (1 . 0))
      ("http://openid.net/signon/1.1" . (1 . 1))
      ("http://openid.net/server/1.1" . (1 . 1))))

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

(defun normalize-identifier (id)
  "Normalize a user-given identifier ID, return alist token.

An XRDS URL for Yadis discovery discovered by a HEAD request may be
also included in the token.."
  ;; OpenID Authentication 2.0 Final, Section 7.2.  Normalization

  ;; 1., 2.
  (let ((possible-xri (if (string= "xri://" (subseq id 0 6))
                          (subseq id 6)
                          id)))
    (when (member (char possible-xri 0)
                  '(#\= #\@ #\+ #\$ #\! #\())
      ;; input SHOULD be treated as an XRI
      (error "XRI identifiers are not supported.")))

  ;; 3. the input SHOULD be treated as an http URL

  ;; if it does not include a "http" or "https" scheme, the Identifier
  ;; MUST be prefixed with the string "http://"
  (unless (or (string= (subseq id 0 5) "http:")
              (string= (subseq id 0 6) "https:"))
    (setf id (concatenate 'string "http://" id)))
  
  (let ((id (uri id)))
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
      (let ((rv ())
            (xrds (assoc :x-xrds-location headers)))
        (push (cons :claimed-id uri) rv)
        (when xrds
          (push xrds rv))
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

(defun perform-html-discovery (id body)
  (labels ((remember (name key rel link)
             "When NAME is in REL, push (CONS KEY (HREF LINK)) to ID."
             (when (member name rel :test #'string-equal)
               (push (cons key (getf (cdar link) :href)) id)))

           (handle-link-tag (link       ; ((:link attrs...))
                             &aux
                             (rel (split-sequence #\Space (getf (cdar link) :rel))))
             (remember "openid2.provider" :op-endpoint-url rel link)
             (remember "openid2.local_id" :op-local-identifier rel link)
             (remember "openid.server" :v1.op-endpoint-url rel link)
             (remember "openid.delegate" :v1.op-local-identifier rel link)) ; FIXME:delegate?

           (handle-meta-tag (meta)
             (when (string-equal "X-XRDS-Location" (getf (cdar meta) :http-equiv))
               (push (cons :x-xrds-location (getf (cdar meta) :content)) id))))

    (parse-html body :callback-only t
                :callbacks (acons :link #'handle-link-tag
                                  (acons :meta #'handle-meta-tag
                                         nil))))
  id)

(defun perform-xrds-discovery (id body
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

  (when endpoint
    (progn (push (cons :op-endpoint-url endpoint) id)
           (when oplocal
             (push (cons :op-local-identifier oplocal) id))))

  (when v1type
    (push (cons :v1.type v1type) id)
    (push (cons :v1.op-endpoint-url v1endpoint) id)
    (when v1oplocal
      (push (cons :v1.op-local-identifier v1oplocal) id)))

  id)

(defun discover (id
                 &aux
                 (id-x-xrds-location (assoc :x-xrds-location id))
                 (request-uri (cdr (or id-x-xrds-location
                                       (assoc :claimed-id id))))
                 discovered-id)
  "Perform discovery."
  ;; OpenID Authentication 2.0 Final, Section 7.3.  Discovery
  (setf discovered-id
        (let ((*text-content-types* (append '(("application" . "xhtml+xml") ("application" . "xrds+xml"))
                                            *text-content-types*)))
          (multiple-value-bind
                (body status-code headers uri stream must-close reason-phrase)
              (http-request request-uri :additional-headers '((:accept-encoding "")))
            (declare (ignore stream must-close))
      
            (unless (= 2 (floor (/ status-code 100))) ; 2xx succesful response
              (error "Could not reach ~A: ~A ~A" request-uri status-code reason-phrase))

            ;; X-XRDS-Location: header check
            (let ((x-xrds-location (assoc :x-xrds-location headers)))
              (when (and x-xrds-location
                         (not (uri= (uri (cdr x-xrds-location)) uri)))
                (if id-x-xrds-location
                    (setf (cdr id-x-xrds-location) (cdr x-xrds-location))
                    (push x-xrds-location id))
                (return-from discover
                  (discover id))))

            ;; Content-Type: check
            (let ((content-type (multiple-value-list (get-content-type headers))))
              (setf (cddr content-type) nil) ; drop parameters
              (cond
                ((or id-x-xrds-location ; wikitravel returns XRDS as
                                        ; text/html, so when we asked
                                        ; explicitly for XRDS we assume we
                                        ; receive XRDS.
                     (equalp '("application" "xrds+xml") content-type))
                 (perform-xrds-discovery id body))

                ((member content-type '(("text" "html")
                                        ("application" "xhtml+xml"))
                         :test #'equalp)
                 (let ((new-id (perform-html-discovery id body)))
                   (when (assoc :x-xrds-location new-id) ; XRDS location found in HTML
                     (return-from discover
                       ;; TODO: catch errors and fall back to HTML-discovered info
                       (discover (remove-if #'(lambda (item)             ; go through Yadis discovery
                                                (member (car item)
                                                        '(:op-endpoint-url :op-local-identifier
                                                          :v1.op-endpoint-url :v1.op-local-identifier)))
                                            new-id))))
                   new-id))

                (t (error "Unsupported content-type ~S at ~A" content-type request-uri)))))))

  ;; Normalize endpoint and protocol version info
  (cond ((assoc :op-endpoint-url discovered-id)
         (push (cons :protocol-version (cons 2 0)) discovered-id))

        ((assoc :v1.op-endpoint-url discovered-id)

         (setf (car (assoc :v1.op-endpoint-url discovered-id)) :op-endpoint-url)

         (let ((oploc (assoc :v1.op-endpoint-url discovered-id)))
           (when oploc
             (setf (car oploc) :op-endpoint-url)))

         (let* ((type (assoc :v1.type discovered-id)))
           (if type
               (setf (car type) :protocol-version
                     (cdr type) (or (cdr (assoc (cdr type) +protocol-versions+ :test #'equal))
                                    (cons 1 1)))
               (push (cons :protocol-version (cons 1 1)) discovered-id))))

        (t (error "Discovery unsuccessful: ~S." discovered-id)))

  ;; Set endpoint URL as URI (will need schema info for association)
  (let ((ep (assoc :op-endpoint-url discovered-id)))
    (setf (cdr ep) (uri (cdr ep))))

  discovered-id)

