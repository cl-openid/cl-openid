(defpackage #:cl-openid
  (:use #:common-lisp
        #:drakma
        #-allegro puri #+allegro net.uri
        #:net.html.parser
        #:split-sequence
        #:cl-base64
        #:trivial-utf-8
        #:ironclad)
  (:shadowing-import-from :cl #:null) ; Ironclad shadows NULL, we don't want to
  (:export #:in-ns #:message-field #:message-v2-p #:make-message #:copy-message  ; Message API
           #:relying-party #:realm #:root-uri   ; RP class
	   #:auth-process #:auth-process-p #:protocol-version-major #:protocol-version-minor #:protocol-version #:claimed-id #:op-local-id #:return-to #:xrds-location #:endpoint-uri #:timestamp ; AUTH-PROCESS structure
           #:initiate-authentication #:+authproc-handle-parameter+ #:handle-indirect-response ; RP API
           #:openid-assertion-error #:code #:reason #:authproc #:message ; assertion error condition
           #:openid-provider #:op-endpoint-uri  ; OP class
           #:handle-checkid-immediate #:handle-checkid-setup #:with-indirect-error-handler #:signal-indirect-error #:handle-openid-provider-request ; OP API
           #:successful-response #:cancel-response #:+indirect-response-code+ ; responses
           ))
