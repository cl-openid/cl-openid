(defpackage #:cl-openid
  (:use #:common-lisp
        #:drakma
        #:puri
        #:net.html.parser
        #:split-sequence
        #:cl-base64
        #:trivial-utf-8
        #:ironclad
        #:bordeaux-threads)
  (:shadowing-import-from :cl #:null) ; Ironclad shadows NULL, we don't want to
  (:export #:in-ns #:message-field #:message-v2-p #:make-message #:copy-message  ; Message API
           #:relying-party #:realm #:root-uri   ; RP class
	   #:auth-process #:auth-process-p #:protocol-version-major #:protocol-version-minor #:protocol-version #:claimed-id #:op-local-id #:return-to #:xrds-location #:provider-endpoint-uri #:timestamp ; AUTH-PROCESS structure
           #:initiate-authentication #:+authproc-handle-parameter+ #:handle-indirect-response ; RP API
           #:openid-assertion-error #:code #:reason #:authproc #:message ; assertion error condition
           #:openid-provider #:endpoint-uri  ; OP class
           #:handle-checkid-immediate #:handle-checkid-setup #:user-setup-url #:handle-openid-provider-request ; OP API
           #:successful-response #:cancel-response #:+indirect-response-code+ ; responses
           #:with-indirect-error-handler #:signal-indirect-error #:handle-openid-provider-request ; indirect error responses
           ))
