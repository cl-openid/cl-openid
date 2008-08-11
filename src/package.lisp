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
  (:export #:relying-party #:realm #:root-uri  ; RP class
           #:initiate-authentication #:+authproc-handle-parameter+ #:handle-indirect-response #:handle-openid-provider-request ; RP API
           #:openid-assertion-error #:code  ; assertion error condition
           #:openid-provider #:op-endpoint-uri  ; OP class
           #:allow-unencrypted-association-p #:handle-checkid-immediate #:handle-checkid-setup ; OP API
           #:successful-response #:cancel-response #:+indirect-response-code+ ; responses
           ))
